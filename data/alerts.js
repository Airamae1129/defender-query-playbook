// Defender Query Playbook: alert library.
// This file is plain JSON wrapped in one assignment so index.html can load it
// when opened straight from disk (browsers block fetch() of local .json files).
// Edit the JSON below; keep the first and last lines as they are.
// Run `node scripts/validate.mjs` after editing.
window.PLAYBOOK_ALERTS = [
  {
    "id": "user-signins",
    "name": "User investigation: successful sign-ins",
    "cat": "Identity",
    "src": "Entra ID / Sentinel",
    "sev": "info",
    "mitre": [
      "T1078"
    ],
    "playbook": true,
    "summary": "Baseline where, how and on which devices a user signs in. Use it alongside any identity alert to separate normal behaviour from attacker activity.",
    "steps": [
      {
        "ctx": "Who is the user? (IdentityInfo: job title, department, country, manager, roles, risk)",
        "kql": "IdentityInfo\n| where Timestamp > ago({{BASELINE}})\n| where AccountUpn =~ \"{{UPN}}\"\n| summarize arg_max(Timestamp, *) by AccountObjectId\n| project LastSeen = Timestamp, AccountUpn, AccountDisplayName, JobTitle, Department,\n          CompanyName = column_ifexists(\"CompanyName\", \"\"), Manager = column_ifexists(\"Manager\", \"\"),\n          City, Country, EmailAddress, Phone = column_ifexists(\"Phone\", \"\"),\n          IsAccountEnabled, TenantMembershipType, IdentityEnvironment,\n          Created = column_ifexists(\"CreatedDateTime\", datetime(null)),\n          RiskLevel, RiskLevelDetails, CriticalityLevel,\n          AssignedRoles = column_ifexists(\"AssignedRoles\", dynamic(null)),\n          PimRoles = column_ifexists(\"PrivilegedEntraPimRoles\", dynamic(null)),\n          BlastRadius = column_ifexists(\"BlastRadius\", \"\"),\n          AccountName, AccountDomain = column_ifexists(\"AccountDomain\", \"\"), OnPremSid, AccountObjectId",
        "read": "Compare <b>Country</b> and <b>City</b> with the sign-in locations in the next steps; a sign-in from a country the user isn't based in stands out. <b>JobTitle</b>, <b>Department</b> and <b>AssignedRoles</b> / <b>PimRoles</b> show how much damage the account could do (admins and finance staff are higher priority). <b>RiskLevel</b> is Entra ID's own risk rating, and <b>IsAccountEnabled</b> false means the account is already disabled. IdentityInfo keeps a row per change or per day, so the query shows the latest one. Columns only some licences or Sentinel UEBA provide (Manager, CompanyName, BlastRadius, PIM roles) come back empty when missing."
      },
      {
        "ctx": "Check the user's successful sign-in logs",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,\n          City = tostring(LocationDetails.city),\n          State = tostring(LocationDetails.state),\n          Country = tostring(LocationDetails.countryOrRegion),\n          DeviceName = tostring(DeviceDetail.displayName),\n          OS = tostring(DeviceDetail.operatingSystem),\n          Browser = tostring(DeviceDetail.browser),\n          IsCompliant = tostring(DeviceDetail.isCompliant),\n          IsManaged = tostring(DeviceDetail.isManaged),\n          ClientAppUsed, AuthenticationRequirement,\n          ConditionalAccessStatus, RiskLevelDuringSignIn\n| order by TimeGenerated desc",
        "read": "Look for sign-ins with no device name, an unmanaged or non-compliant device, <b>singleFactorAuthentication</b>, or a country the user has never used."
      },
      {
        "ctx": "Check the user's successful sign-in logs excluding specific countries",
        "kql": "let ExcludedCountries = dynamic([{{XCOUNTRIES}}]);\nSigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| where Country !in~ (ExcludedCountries)\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,\n          City = tostring(LocationDetails.city),\n          State = tostring(LocationDetails.state),\n          Country,\n          DeviceName = tostring(DeviceDetail.displayName),\n          OS = tostring(DeviceDetail.operatingSystem),\n          Browser = tostring(DeviceDetail.browser),\n          IsCompliant = tostring(DeviceDetail.isCompliant),\n          IsManaged = tostring(DeviceDetail.isManaged),\n          ClientAppUsed, AuthenticationRequirement,\n          ConditionalAccessStatus, RiskLevelDuringSignIn\n| order by TimeGenerated desc",
        "read": "Same as step 1, but sign-ins from the countries in <b>Exclude countries</b> (2-letter codes, e.g. HK, AU) are removed, so only unexpected locations are left. With Exclude countries empty, every sign-in is shown."
      },
      {
        "ctx": "Did the user sign in from an IP not seen before the look-back window?",
        "kql": "let KnownIPs = SigninLogs\n    | where TimeGenerated between (ago({{BASELINE}}) .. ago({{LOOKBACK}}))\n    | where UserPrincipalName =~ \"{{UPN}}\" and ResultType == \"0\"\n    | distinct IPAddress;\nSigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\" and ResultType == \"0\"\n| where IPAddress !in (KnownIPs)\n| project TimeGenerated, IPAddress, Country = tostring(LocationDetails.countryOrRegion),\n          City = tostring(LocationDetails.city), AppDisplayName, ClientAppUsed,\n          UserAgent, AuthenticationRequirement",
        "read": "Each row is a new IP for this user. Check each one against the IoC entry below and your threat intel."
      },
      {
        "ctx": "Same check without Sentinel (Defender XDR only)",
        "kql": "EntraIdSignInEvents\n| where Timestamp > ago({{BASELINE}})\n| where AccountUpn =~ \"{{UPN}}\" and ErrorCode == 0\n| summarize SignIns = count(), Apps = make_set(Application, 20),\n            First = min(Timestamp), Last = max(Timestamp)\n            by IPAddress, Country, City\n| order by Last desc",
        "read": "EntraIdSignInEvents needs an Entra ID P2 licence. It replaces AADSignInEventsBeta from 19 Oct 2026."
      },
      {
        "ctx": "Sign-ins from the countries entered (Countries field)",
        "kql": "let Countries = dynamic([{{COUNTRIES}}]);\nSigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| where Country in~ (Countries)\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,\n          City = tostring(LocationDetails.city),\n          State = tostring(LocationDetails.state),\n          Country,\n          DeviceName = tostring(DeviceDetail.displayName),\n          OS = tostring(DeviceDetail.operatingSystem),\n          Browser = tostring(DeviceDetail.browser),\n          IsCompliant = tostring(DeviceDetail.isCompliant),\n          IsManaged = tostring(DeviceDetail.isManaged),\n          ClientAppUsed, AuthenticationRequirement,\n          ConditionalAccessStatus, RiskLevelDuringSignIn\n| order by TimeGenerated desc",
        "read": "Shows only sign-ins from the countries you typed in <b>Countries</b> (2-letter codes, e.g. HK, AU). Use it to confirm the user really signs in from a country named in the alert."
      },
      {
        "ctx": "Sign-ins excluding the countries entered (Countries field)",
        "kql": "let Countries = dynamic([{{COUNTRIES}}]);\nSigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| where Country !in~ (Countries)\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,\n          City = tostring(LocationDetails.city),\n          State = tostring(LocationDetails.state),\n          Country,\n          DeviceName = tostring(DeviceDetail.displayName),\n          OS = tostring(DeviceDetail.operatingSystem),\n          Browser = tostring(DeviceDetail.browser),\n          IsCompliant = tostring(DeviceDetail.isCompliant),\n          IsManaged = tostring(DeviceDetail.isManaged),\n          ClientAppUsed, AuthenticationRequirement,\n          ConditionalAccessStatus, RiskLevelDuringSignIn\n| order by TimeGenerated desc",
        "read": "Shows every sign-in <b>except</b> the countries you typed. Put the user's normal countries in <b>Countries</b> and anything left is worth a closer look, especially with no device name, an unmanaged device or <b>singleFactorAuthentication</b>."
      }
    ],
    "fp": "Travel, mobile networks and VPNs create new IPs and countries. Confirm with the user before escalating."
  },
  {
    "id": "user-signins-excl-country",
    "name": "User investigation: sign-ins outside expected countries",
    "cat": "Identity",
    "src": "Entra ID / Sentinel",
    "sev": "info",
    "mitre": [
      "T1078"
    ],
    "playbook": true,
    "summary": "The user's successful sign-ins with the countries they normally work from filtered out, so only unexpected locations are left. Put the user's home and travel countries in Exclude countries as 2-letter codes (for example HK, AU).",
    "steps": [
      {
        "ctx": "Which countries does the user sign in from? (pick the ones to exclude)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\" and ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| summarize SignIns = count(), IPs = dcount(IPAddress), First = min(TimeGenerated), Last = max(TimeGenerated)\n            by UserPrincipalName, Country\n| order by SignIns desc",
        "read": "The countries with most sign-ins over weeks are usually the user's normal locations. Type those into <b>Exclude countries</b>; the next steps then show only the rest."
      },
      {
        "ctx": "Check the user's successful sign-in logs, excluding expected countries",
        "kql": "let ExcludedCountries = dynamic([{{XCOUNTRIES}}]);\nSigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| where Country !in~ (ExcludedCountries)\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,\n          City = tostring(LocationDetails.city),\n          State = tostring(LocationDetails.state),\n          Country,\n          DeviceName = tostring(DeviceDetail.displayName),\n          OS = tostring(DeviceDetail.operatingSystem),\n          Browser = tostring(DeviceDetail.browser),\n          IsCompliant = tostring(DeviceDetail.isCompliant),\n          IsManaged = tostring(DeviceDetail.isManaged),\n          ClientAppUsed, AuthenticationRequirement,\n          ConditionalAccessStatus, RiskLevelDuringSignIn\n| order by TimeGenerated desc",
        "read": "Every row is a sign-in from a country you didn't exclude. Look harder at rows with no device name, an unmanaged or non-compliant device, or <b>singleFactorAuthentication</b>. With Exclude countries empty, all sign-ins are shown."
      },
      {
        "ctx": "Did the user sign in from a new IP outside the expected countries?",
        "kql": "let ExcludedCountries = dynamic([{{XCOUNTRIES}}]);\nlet KnownIPs = SigninLogs\n    | where TimeGenerated between (ago({{BASELINE}}) .. ago({{LOOKBACK}}))\n    | where UserPrincipalName =~ \"{{UPN}}\" and ResultType == \"0\"\n    | distinct IPAddress;\nSigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\" and ResultType == \"0\"\n| where IPAddress !in (KnownIPs)\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| where Country !in~ (ExcludedCountries)\n| project TimeGenerated, IPAddress, Country,\n          City = tostring(LocationDetails.city), AppDisplayName, ClientAppUsed,\n          UserAgent, AuthenticationRequirement",
        "read": "A new IP in an unexpected country is the strongest sign of a compromised account here. Check it against the IoC entry and your threat intel, and confirm with the user."
      },
      {
        "ctx": "Same check without Sentinel (Defender XDR only)",
        "kql": "let ExcludedCountries = dynamic([{{XCOUNTRIES}}]);\nEntraIdSignInEvents\n| where Timestamp > ago({{BASELINE}})\n| where AccountUpn =~ \"{{UPN}}\" and ErrorCode == 0\n| where Country !in~ (ExcludedCountries)\n| summarize SignIns = count(), Apps = make_set(Application, 20),\n            First = min(Timestamp), Last = max(Timestamp)\n            by IPAddress, Country, City\n| order by Last desc",
        "read": "EntraIdSignInEvents needs an Entra ID P2 licence. It replaces AADSignInEventsBeta from 19 Oct 2026."
      }
    ],
    "fp": "Business travel, roaming mobile data and VPN or cloud-proxy exits (which can show another country) all appear here. Add confirmed travel countries to Exclude countries and re-run."
  },
  {
    "id": "user-mailbox-audit",
    "name": "User investigation: mailbox and account audit",
    "cat": "Identity",
    "src": "Exchange Online / Entra ID (Sentinel)",
    "sev": "info",
    "mitre": [
      "T1114.003",
      "T1564.008",
      "T1098",
      "T1556"
    ],
    "playbook": true,
    "summary": "After a suspicious sign-in, check what the account did: inbox rules, forwarding, delegation, mail sent or deleted, and changes to MFA, passwords, devices, app consent and roles.",
    "steps": [
      {
        "ctx": "Mailbox audit: inbox rules, forwarding, delegation, mail sent (look-back window)",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserId =~ \"{{UPN}}\" or MailboxOwnerUPN =~ \"{{UPN}}\"\n| where Operation in~ (\"New-InboxRule\",\"Set-InboxRule\",\"UpdateInboxRules\",\"Remove-InboxRule\",\n                       \"Set-Mailbox\",\"Add-MailboxPermission\",\"Add-RecipientPermission\",\"Set-OwaMailboxPolicy\",\n                       \"Send\",\"SendAs\",\"SendOnBehalf\",\"HardDelete\",\"SoftDelete\",\"MoveToDeletedItems\",\n                       \"MailItemsAccessed\",\"New-TransportRule\",\"Set-TransportRule\")\n| extend Params = tostring(Parameters)\n| extend Suspicious = iff(Params has_any (\"ForwardTo\",\"RedirectTo\",\"ForwardAsAttachmentTo\",\"ForwardingSmtpAddress\",\"DeleteMessage\",\"MoveToFolder\",\"RSS\"), \"⚠ Review\", \"\")\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated), IPs = make_set(ClientIP, 10), Sample = take_any(substring(Params, 0, 300))\n    by Operation, Suspicious\n| order by Suspicious desc, n desc",
        "read": "Rows marked <b>⚠ Review</b> have forwarding, redirect, delete or move-to-folder parameters, which is the classic attacker inbox rule. Also look for <b>Add-MailboxPermission</b> / <b>SendAs</b> granted to an unknown account, and Send or HardDelete bursts from IPs the user doesn't normally use. Set the look-back to 14d to match the original check."
      },
      {
        "ctx": "Audit log activity for the user (baseline window, 30 days)",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{BASELINE}})\n| extend Initiator = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),\n         InitiatorIP = tostring(InitiatedBy.user.ipAddress),\n         Target = tostring(TargetResources[0].userPrincipalName),\n         TargetName = tostring(TargetResources[0].displayName),\n         ModifiedProps = tostring(TargetResources[0].modifiedProperties)\n| where Initiator =~ \"{{UPN}}\" or Target =~ \"{{UPN}}\" or tostring(TargetResources) has \"{{UPN}}\"\n| extend RiskArea = case(\n    OperationName has_any (\"security info\",\"StrongAuthentication\",\"authentication method\",\"MFA\"), \"MFA / Security Info\",\n    OperationName has_any (\"password\",\"Reset\"), \"Password\",\n    OperationName has_any (\"device\",\"Register device\",\"Add registered owner\",\"Add registered users\"), \"Device Registration\",\n    OperationName has_any (\"Consent\",\"OAuth2PermissionGrant\",\"Add app role assignment\",\"Add delegated permission\"), \"App Consent\",\n    OperationName has_any (\"member to role\",\"role\"), \"Role Change\",\n    OperationName has_any (\"Update user\",\"Disable account\",\"Enable account\"), \"User Update\",\n    OperationName has_any (\"Conditional Access\",\"policy\"), \"Policy Change\",\n    \"Other\")\n| project TimeGenerated, RiskArea, OperationName, Result, Initiator, InitiatorIP, Target, TargetName,\n          Category, LoggedByService, CorrelationId, ModifiedProps\n| order by case(RiskArea in (\"MFA / Security Info\",\"App Consent\",\"Device Registration\",\"Role Change\"), 0, 1) asc, TimeGenerated desc",
        "read": "Rows sort with the riskiest areas first: <b>MFA / Security Info</b>, <b>App Consent</b>, <b>Device Registration</b> and <b>Role Change</b>. A new MFA method or registered device shortly after an unusual sign-in, initiated from an unfamiliar InitiatorIP, points to account takeover."
      }
    ],
    "fp": "Users setting up a new phone (new MFA method and device registration), helpdesk password resets, and legitimate out-of-office or folder-sorting inbox rules. Confirm with the user or helpdesk before escalating."
  },
  {
    "id": "bf-entra-device",
    "name": "Brute force attack against an Entra-authenticated Windows device",
    "cat": "Identity",
    "src": "Defender for Endpoint / Entra ID",
    "sev": "medium",
    "mitre": [
      "T1110",
      "T1110.003"
    ],
    "playbook": true,
    "summary": "Repeated failed logons against a Windows device that authenticates with Entra ID. Decide whether the source IPs are normal for the tenant, whether accounts show real password failures, and whether any attempt succeeded.",
    "steps": [
      {
        "ctx": "Are the alert IPs normal for the tenant?",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where IPAddress in ({{IPS}})\n| summarize SignIns = count(), Success = countif(ResultType == \"0\"),\n            Users = dcount(UserPrincipalName), SampleUsers = make_set(UserPrincipalName, 15),\n            City = take_any(tostring(LocationDetails.city)),\n            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)\n            by IPAddress",
        "read": "An IP with many successful sign-ins from many users over weeks is likely an office or VPN egress. An IP with no history, or only failures, is suspicious."
      },
      {
        "ctx": "Password and lockout errors for the targeted users (real brute-force indicators)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName in~ ({{UPNS}})\n| where ResultType in (\"50126\", \"50053\", \"50055\", \"50057\", \"53003\", \"500121\")\n| summarize Count = count(), IPs = make_set(IPAddress),\n            Countries = make_set(tostring(LocationDetails.countryOrRegion)),\n            Apps = make_set(AppDisplayName)\n            by UserPrincipalName, ResultType, ResultDescription\n| order by Count desc",
        "read": "<b>50126</b> wrong username or password, <b>50053</b> account locked or sign-in from a malicious IP, <b>50055</b> password expired, <b>50057</b> account disabled, <b>53003</b> blocked by Conditional Access, <b>500121</b> MFA failed. Your original query also listed 50074 and 50076; those are normal MFA prompts, so they are left out here to avoid inflating counts."
      },
      {
        "ctx": "Did any attempt against the device succeed?",
        "kql": "DeviceLogonEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| summarize Failed = countif(ActionType == \"LogonFailed\"),\n            Success = countif(ActionType == \"LogonSuccess\"),\n            Accounts = make_set(AccountName, 25), LogonTypes = make_set(LogonType)\n            by RemoteIP, RemoteIPType\n| order by Failed desc",
        "read": "A successful logon from an IP that also has many failures should be treated as a compromise: isolate the device and reset the account."
      }
    ],
    "fp": "Users with a cached old password (phone mail apps, mapped drives) generate steady 50126 failures from known IPs."
  },
  {
    "id": "ioc-ip",
    "name": "Network session matched an IoC (IP address)",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "medium",
    "mitre": [
      "T1071"
    ],
    "playbook": true,
    "summary": "A device talked to an IP on a threat-intel list. Find every device and process that touched it, check whether it logged on to anything, and whether it appears in cloud sign-ins.",
    "steps": [
      {
        "ctx": "All network activity with the IP across the tenant",
        "kql": "DeviceNetworkEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where RemoteIP == \"{{IP}}\"\n| summarize Events = count(), Actions = make_set(ActionType),\n            LocalPorts = make_set(LocalPort), RemotePorts = make_set(RemotePort),\n            Processes = make_set(InitiatingProcessFileName),\n            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)\n            by DeviceName, LocalIP\n| order by Events desc",
        "read": "<b>InboundConnectionAccepted</b> on RDP (3389) or SMB (445) means an internet-exposed service. Browser processes connecting out usually means a user visited a site. Your original note mentioned one IP in the context line and another in the query; here a single field drives both."
      },
      {
        "ctx": "Logon attempts from the IP (a successful logon here means compromise)",
        "kql": "DeviceLogonEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where RemoteIP == \"{{IP}}\"\n| summarize Success = countif(ActionType == \"LogonSuccess\"),\n            Failed = countif(ActionType == \"LogonFailed\"),\n            Accounts = make_set(AccountName, 50),\n            FailureReasons = make_set(FailureReason),\n            LogonTypes = make_set(LogonType, 10),\n            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)\n            by DeviceName",
        "read": "Any Success greater than 0 means the attacker got in. Isolate the device and reset the listed accounts."
      },
      {
        "ctx": "Does the IP show up in Entra sign-ins or cloud app activity?",
        "kql": "union isfuzzy=true\n    (EntraIdSignInEvents\n        | where Timestamp > ago({{LOOKBACK}}) and IPAddress == \"{{IP}}\"\n        | project Timestamp, Source = \"Entra sign-in\", Account = AccountUpn, Detail = Application),\n    (CloudAppEvents\n        | where Timestamp > ago({{LOOKBACK}}) and IPAddress == \"{{IP}}\"\n        | project Timestamp, Source = \"Cloud app\", Account = AccountDisplayName, Detail = ActionType)\n| summarize Events = count(), Details = make_set(Detail, 20),\n            First = min(Timestamp), Last = max(Timestamp) by Source, Account",
        "read": "Results here mean the IP is touching identities, not just one device. Widen the investigation to those accounts."
      },
      {
        "ctx": "Did any endpoint or firewall see the IoC IPs? (baseline window, 30 days, MDE + firewall)",
        "kql": "union isfuzzy=true\n(\n    DeviceNetworkEvents\n    | where Timestamp > ago({{BASELINE}})\n    | where RemoteIP in~ (\"{{IP}}\")\n    | project\n        TimeGenerated = Timestamp,\n        IPAddress = RemoteIP,\n        RemoteUrl,\n        DeviceName,\n        ActionType,\n        SourceTable = \"DeviceNetworkEvents\"\n),\n(\n    CommonSecurityLog\n    | where TimeGenerated > ago({{BASELINE}})\n    | where SourceIP in~ (\"{{IP}}\") or DestinationIP in~ (\"{{IP}}\")\n    | project\n        TimeGenerated,\n        IPAddress = iff(SourceIP in~ (\"{{IP}}\"), SourceIP, DestinationIP),\n        RemoteUrl = RequestURL,\n        DeviceName = Computer,\n        ActionType = DeviceAction,\n        SourceTable = \"CommonSecurityLog\"\n)\n| sort by TimeGenerated desc",
        "read": "Paste every IoC IP into <b>IP address</b>, separated by commas. Rows from <b>DeviceNetworkEvents</b> show which devices connected; rows from <b>CommonSecurityLog</b> show the firewall's view (source or destination) and its action. <b>Allowed</b> or <b>ConnectionSuccess</b> rows are the ones to chase; blocked or denied traffic only shows an attempt. Firewall rows need the CommonSecurityLog (CEF) connector in Sentinel."
      }
    ],
    "fp": "Scanner IPs on threat feeds hit every internet-facing host. Inbound-only, blocked traffic with no logons is usually noise."
  },
  {
    "id": "guest-groups",
    "name": "Guest accounts added in Entra ID groups other than the ones specified",
    "cat": "Identity",
    "src": "Entra ID / Sentinel",
    "sev": "medium",
    "mitre": [
      "T1098",
      "T1136.003"
    ],
    "playbook": true,
    "summary": "A guest (#EXT#) account was added to a group outside the allowed list. Reconstruct how the guest was created and added, whether it was used, and whether the inviter or process does this regularly.",
    "steps": [
      {
        "ctx": "Full audit trail of the account: how it was created, by whom, and which groups it joined",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where TargetResources has \"{{GUEST}}\"\n    or TargetResources has \"{{OBJECTID}}\"\n    or InitiatedBy has \"{{GUEST}}\"\n| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),\n         ActorIP = tostring(InitiatedBy.user.ipAddress),\n         Target = tostring(TargetResources[0].userPrincipalName),\n         Group = tostring(TargetResources[1].displayName),\n         Mods = tostring(TargetResources[0].modifiedProperties)\n| project TimeGenerated, OperationName, Result, Actor, ActorIP, Target, Group, Mods, AdditionalDetails\n| order by TimeGenerated asc",
        "read": "Expect a sequence like invite, user created, invite redeemed, then the group adds. Note whether the actor is a person or an automated app (Approval Management, Cloud Sync)."
      },
      {
        "ctx": "Has the guest account signed in since it was created?",
        "kql": "union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName has \"{{GUEST}}\" or UserId == \"{{OBJECTID}}\"\n| summarize SignIns = count(),\n            Success = countif(ResultType == \"0\"),\n            Failed = countif(ResultType != \"0\"),\n            Apps = make_set(AppDisplayName, 10),\n            IPs = make_set(IPAddress, 10),\n            Countries = make_set(Location, 10),\n            First = min(TimeGenerated), Last = max(TimeGenerated)",
        "read": "Zero sign-ins lowers the urgency. Successful sign-ins to sensitive apps right after the group add raise it."
      },
      {
        "ctx": "Baseline: how often does the same process add external users to groups?",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where OperationName == \"Add member to group\"\n| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),\n         U = tostring(TargetResources[0].userPrincipalName),\n         Grp = tostring(TargetResources[0].modifiedProperties[1].newValue)\n| where U has \"#EXT#\"\n| summarize Adds = count(), Users = dcount(U), SampleUsers = make_set(U, 10),\n            Groups = make_set(Grp, 10), First = min(TimeGenerated), Last = max(TimeGenerated)\n            by Actor",
        "read": "If one actor (for example Microsoft Approval Management) adds many guests to the same broad groups, this alert is a known pattern. Consider tuning the allowed-group list rather than re-investigating each time."
      },
      {
        "ctx": "Guest invitation and redemption history",
        "kql": "AuditLogs\n| where TimeGenerated > ago(90d)\n| where OperationName in (\"Invite external user\", \"Redeem external user invite\", \"Add user\",\n        \"Update user\", \"Invite external user with reset invitation status\")\n| where tostring(TargetResources) has_any (\"{{OBJECTID}}\", \"{{GUEST}}\")\n| project TimeGenerated, OperationName, Result,\n          InvitedBy = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),\n          InviterIP = tostring(InitiatedBy.user.ipAddress),\n          Target = tostring(TargetResources[0].userPrincipalName),\n          AdditionalDetails = tostring(AdditionalDetails)\n| order by TimeGenerated asc",
        "read": "Shows whether this was a one-off invite and who sent it."
      },
      {
        "ctx": "Does the inviter regularly create users or invite guests?",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where tostring(InitiatedBy.user.userPrincipalName) =~ \"{{ACTOR}}\"\n| where OperationName in (\"Add user\", \"Invite external user\", \"Add member to group\")\n| summarize Events = count(),\n            Targets = make_set(tostring(TargetResources[0].userPrincipalName), 20),\n            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)\n            by OperationName, Category\n| order by Events desc",
        "read": "An admin who invites guests every week is routine. An account that has never done this before, or whose own sign-ins look unusual (run the sign-in entry on them), needs a closer look."
      }
    ],
    "fp": "Approved access-package or approval workflows add guests to broad groups such as All Users. Confirm the group list in the analytic rule is current."
  },
  {
    "id": "ps-encoded",
    "name": "Suspicious PowerShell command line",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1059.001",
      "T1027"
    ],
    "summary": "PowerShell ran with encoding, hidden windows or download cradles. Find the command, decode it, and see what it connected to.",
    "steps": [
      {
        "ctx": "Which PowerShell commands ran, and what launched them?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName in~ (\"powershell.exe\", \"pwsh.exe\")\n| where ProcessCommandLine has_any (\"-enc\", \"-encodedcommand\", \"FromBase64String\", \"IEX\",\n        \"Invoke-Expression\", \"DownloadString\", \"DownloadFile\", \"-w hidden\", \"-nop\")\n| project Timestamp, AccountName, InitiatingProcessFileName,\n          InitiatingProcessCommandLine, ProcessCommandLine\n| order by Timestamp desc",
        "read": "A parent of <b>winword.exe</b>, <b>excel.exe</b>, <b>mshta.exe</b> or <b>wscript.exe</b> is much more suspicious than one launched by an IT management agent."
      },
      {
        "ctx": "Decode the encoded payload",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName in~ (\"powershell.exe\", \"pwsh.exe\")\n| extend B64 = extract(@\"(?i)\\s-e(?:nc|ncodedcommand)?\\s+([A-Za-z0-9+/=]{20,})\", 1, ProcessCommandLine)\n| where isnotempty(B64)\n| extend Decoded = base64_decode_tostring(B64)\n| project Timestamp, AccountName, Decoded, ProcessCommandLine",
        "read": "PowerShell encodes in UTF-16, so the decoded text may show gaps between characters. Look for URLs, IPs and further Invoke-Expression calls."
      },
      {
        "ctx": "Did PowerShell connect to the internet?",
        "kql": "DeviceNetworkEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where InitiatingProcessFileName in~ (\"powershell.exe\", \"pwsh.exe\")\n| where RemoteIPType == \"Public\"\n| summarize Connections = count(), Ports = make_set(RemotePort),\n            First = min(Timestamp), Last = max(Timestamp) by RemoteUrl, RemoteIP\n| order by Connections desc",
        "read": "Check each destination against threat intel. Raw IPs and newly registered domains are the strongest signal."
      }
    ],
    "fp": "Configuration tools (Intune scripts, SCCM, monitoring agents) often use -EncodedCommand. Check the parent process and signer."
  },
  {
    "id": "lsass",
    "name": "Credential dumping from LSASS",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1003.001"
    ],
    "summary": "Something read LSASS memory, where Windows keeps credentials. Identify the tool, any dump files, and which accounts' credentials were on the device.",
    "steps": [
      {
        "ctx": "Which processes opened LSASS?",
        "kql": "DeviceEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ActionType == \"OpenProcessApiCall\" and FileName =~ \"lsass.exe\"\n| summarize Count = count(), First = min(Timestamp), Last = max(Timestamp)\n            by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessCommandLine\n| order by Count desc",
        "read": "Unsigned binaries, tools run from user folders, or <b>rundll32</b> loading <b>comsvcs.dll</b> are classic dumping methods."
      },
      {
        "ctx": "Were known dumping tools or techniques used?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ProcessCommandLine has_any (\"comsvcs.dll\", \"MiniDump\", \"procdump\", \"sekurlsa\",\n        \"lsass\", \"nanodump\", \"-ma \")\n| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName",
        "read": "Any hit here is a strong indicator. Collect an investigation package before cleaning up."
      },
      {
        "ctx": "Was a memory dump written to disk?",
        "kql": "DeviceFileEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ActionType == \"FileCreated\" and FileName endswith \".dmp\"\n| project Timestamp, FolderPath, FileName, FileSize, InitiatingProcessFileName, InitiatingProcessCommandLine",
        "read": "A large .dmp created by a non-crash-handler process is likely the stolen LSASS memory."
      },
      {
        "ctx": "Whose credentials were exposed? (accounts logged on to the device)",
        "kql": "DeviceLogonEvents\n| where Timestamp > ago({{BASELINE}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ActionType == \"LogonSuccess\"\n| summarize Logons = count(), LogonTypes = make_set(LogonType), Last = max(Timestamp)\n            by AccountDomain, AccountName, IsLocalAdmin\n| order by Last desc",
        "read": "Reset passwords for every account listed, starting with admins and service accounts."
      }
    ],
    "fp": "Some EDR, backup and password-manager tools read LSASS legitimately. Check the signer and folder path."
  },
  {
    "id": "office-child",
    "name": "Office application spawned a suspicious process",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1566.001",
      "T1204.002"
    ],
    "summary": "Word, Excel, PowerPoint, Outlook or OneNote started a script host or shell, which usually means a malicious document or macro.",
    "steps": [
      {
        "ctx": "What did the Office app launch?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where InitiatingProcessFileName in~ (\"winword.exe\", \"excel.exe\", \"powerpnt.exe\", \"outlook.exe\", \"onenote.exe\")\n| where FileName in~ (\"cmd.exe\", \"powershell.exe\", \"pwsh.exe\", \"wscript.exe\", \"cscript.exe\",\n        \"mshta.exe\", \"rundll32.exe\", \"regsvr32.exe\", \"certutil.exe\", \"bitsadmin.exe\")\n| project Timestamp, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine,\n          FileName, ProcessCommandLine",
        "read": "The InitiatingProcessCommandLine often contains the document path. Copy the file name into the fields above."
      },
      {
        "ctx": "Where did the document come from?",
        "kql": "DeviceFileEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName =~ \"{{FILENAME}}\"\n    or FileName endswith \".docm\" or FileName endswith \".xlsm\" or FileName endswith \".one\"\n    or FileName endswith \".iso\" or FileName endswith \".lnk\"\n| project Timestamp, ActionType, FolderPath, FileName, SHA1, FileOriginUrl,\n          FileOriginReferrerUrl, InitiatingProcessFileName",
        "read": "FileOriginUrl shows the download link. If the file came by email, open the malicious attachment entry with its hash."
      }
    ],
    "fp": "Some finance and reporting add-ins legitimately call cmd or PowerShell. Confirm with the business owner."
  },
  {
    "id": "ransomware",
    "name": "Ransomware behaviour: shadow copy deletion or mass file changes",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1490",
      "T1486"
    ],
    "summary": "Commands that destroy backups, or a burst of file renames, usually come just before or during encryption. Move fast: check spread across the tenant, not just one device.",
    "steps": [
      {
        "ctx": "Which devices ran backup-destroying commands?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ProcessCommandLine has_any (\"delete shadows\", \"shadowcopy delete\", \"resize shadowstorage\",\n        \"recoveryenabled no\", \"bootstatuspolicy ignoreallfailures\", \"delete catalog\")\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n| order by Timestamp asc",
        "read": "More than one device in a short time means the attacker has domain-level access. Escalate to incident response immediately."
      },
      {
        "ctx": "Is a process modifying or renaming files in bulk?",
        "kql": "DeviceFileEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ActionType in (\"FileRenamed\", \"FileModified\")\n| extend Ext = extract(@\"\\.([^.\\\\]+)$\", 1, FileName)\n| summarize Files = dcount(FileName), Extensions = make_set(Ext, 20)\n            by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)\n| where Files > 200\n| order by Files desc",
        "read": "A single unusual extension appearing across hundreds of files is a strong encryption signal."
      },
      {
        "ctx": "Is a device scanning or spreading over SMB?",
        "kql": "DeviceNetworkEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where RemotePort == 445 and RemoteIPType == \"Private\"\n| summarize Targets = dcount(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)\n| where Targets > 20\n| order by Targets desc",
        "read": "File servers and backup tools connect to many hosts normally. A workstation doing it is the concern."
      }
    ],
    "fp": "Backup software and system restore maintenance can resize or delete shadow copies. Check the parent process and schedule."
  },
  {
    "id": "persistence",
    "name": "Persistence: scheduled task or Run key",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "medium",
    "mitre": [
      "T1053.005",
      "T1547.001"
    ],
    "summary": "A new scheduled task or Run key lets malware survive a reboot. List new ones on the device and what they launch.",
    "steps": [
      {
        "ctx": "Were scheduled tasks created from the command line?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName =~ \"schtasks.exe\" and ProcessCommandLine has \"/create\"\n| project Timestamp, AccountName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine",
        "read": "Look at the /tr value: tasks that run scripts from AppData, Temp or Public folders are suspicious."
      },
      {
        "ctx": "All scheduled tasks created on the device",
        "kql": "DeviceEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ActionType == \"ScheduledTaskCreated\"\n| extend TaskName = tostring(parse_json(AdditionalFields).TaskName)\n| project Timestamp, TaskName, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields",
        "read": "Catches tasks created through APIs rather than schtasks.exe. AdditionalFields holds the task content."
      },
      {
        "ctx": "Were Run or RunOnce registry keys changed?",
        "kql": "DeviceRegistryEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ActionType == \"RegistryValueSet\"\n| where RegistryKey has @\"\\CurrentVersion\\Run\"\n| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData,\n          InitiatingProcessFileName, InitiatingProcessAccountName",
        "read": "Compare RegistryValueData with known software installed on the device."
      }
    ],
    "fp": "Software installers and updaters create tasks and Run keys constantly. Focus on unsigned binaries and user-writable paths."
  },
  {
    "id": "lolbin",
    "name": "Living-off-the-land binary used to download or run code",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "medium",
    "mitre": [
      "T1105",
      "T1218"
    ],
    "summary": "Built-in Windows tools (certutil, bitsadmin, mshta, regsvr32, rundll32) were used in ways that download or launch payloads.",
    "steps": [
      {
        "ctx": "Which system binaries were abused, and how?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where (FileName =~ \"certutil.exe\" and ProcessCommandLine has_any (\"urlcache\", \"-decode\", \"split\"))\n     or (FileName =~ \"bitsadmin.exe\" and ProcessCommandLine has \"/transfer\")\n     or (FileName =~ \"mshta.exe\" and ProcessCommandLine has_any (\"http\", \"javascript\", \"vbscript\"))\n     or (FileName =~ \"regsvr32.exe\" and ProcessCommandLine has_any (\"/i:http\", \"scrobj.dll\"))\n     or (FileName =~ \"rundll32.exe\" and ProcessCommandLine has \"javascript:\")\n| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName",
        "read": "The URL in the command line is your next IoC. Add it to the Domain field and run the malicious link entry."
      },
      {
        "ctx": "Did these binaries reach the internet?",
        "kql": "DeviceNetworkEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where InitiatingProcessFileName in~ (\"certutil.exe\", \"bitsadmin.exe\", \"mshta.exe\", \"regsvr32.exe\", \"rundll32.exe\")\n| where RemoteIPType == \"Public\"\n| project Timestamp, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessCommandLine",
        "read": "certutil reaching Microsoft certificate URLs is normal. Anything else is not."
      }
    ],
    "fp": "certutil contacts Microsoft CRL and certificate endpoints during normal operation."
  },
  {
    "id": "av-detect",
    "name": "Antivirus detection: did the malware run?",
    "cat": "Endpoint",
    "src": "Defender Antivirus",
    "sev": "medium",
    "mitre": [
      "T1204"
    ],
    "summary": "Defender Antivirus flagged a file. The key question is whether it was blocked before running or executed first.",
    "steps": [
      {
        "ctx": "What was detected, and was it remediated?",
        "kql": "DeviceEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ActionType == \"AntivirusDetection\"\n| extend Info = parse_json(AdditionalFields)\n| project Timestamp, FileName, FolderPath, SHA1,\n          ThreatName = tostring(Info.ThreatName), WasRemediated = tostring(Info.WasRemediated),\n          InitiatingProcessFileName",
        "read": "Copy the SHA1 into the fields above. WasRemediated = false needs manual cleanup."
      },
      {
        "ctx": "Did the file ever execute?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{BASELINE}})\n| where SHA1 == \"{{SHA1}}\" or InitiatingProcessSHA1 == \"{{SHA1}}\"\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,\n          InitiatingProcessFileName, InitiatingProcessSHA1",
        "read": "No rows means it never ran, which usually closes the alert. Rows where it is the initiating process show what it did next."
      },
      {
        "ctx": "How widespread is the file?",
        "kql": "DeviceFileEvents\n| where Timestamp > ago({{BASELINE}})\n| where SHA1 == \"{{SHA1}}\"\n| summarize Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 25),\n            Paths = make_set(FolderPath, 10), First = min(Timestamp), Last = max(Timestamp)",
        "read": "More than one device means a distribution channel (email, shared drive, software deployment) that needs blocking."
      }
    ],
    "fp": "Potentially unwanted apps (PUA) and hacking tools used by IT staff trigger detections that are expected."
  },
  {
    "id": "tamper",
    "name": "Defender tampering or antivirus disabled",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1562.001"
    ],
    "summary": "Someone tried to turn off real-time protection, add exclusions or stop the Defender service. Attackers do this right before running their payload.",
    "steps": [
      {
        "ctx": "Which commands tried to weaken Defender?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ProcessCommandLine has_any (\"Set-MpPreference\", \"DisableRealtimeMonitoring\", \"Add-MpPreference\",\n        \"ExclusionPath\", \"ExclusionProcess\", \"stop WinDefend\", \"config WinDefend\")\n| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName",
        "read": "Exclusions for Temp, AppData or a whole drive letter are an attacker's favourite. Check what was added."
      },
      {
        "ctx": "Were Defender policy registry values changed?",
        "kql": "DeviceRegistryEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where RegistryKey has @\"\\Microsoft\\Windows Defender\"\n| where ActionType == \"RegistryValueSet\"\n| project Timestamp, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName",
        "read": "DisableAntiSpyware or DisableRealtimeMonitoring set to 1, or new entries under Exclusions, are the values to look for."
      },
      {
        "ctx": "Did tamper protection block an attempt?",
        "kql": "DeviceEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ActionType == \"TamperingAttempt\"\n| project Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields",
        "read": "A blocked attempt still means someone tried. Look at what ran in the minutes around it."
      }
    ],
    "fp": "Admins sometimes add exclusions for line-of-business apps. Confirm against a change ticket."
  },
  {
    "id": "lateral",
    "name": "Lateral movement: PsExec, WMI or remote services",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1021.002",
      "T1047",
      "T1569.002"
    ],
    "summary": "Remote execution tools were used on the device. Find where the session came from and where else the account went.",
    "steps": [
      {
        "ctx": "What was executed remotely?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName in~ (\"psexec.exe\", \"psexesvc.exe\", \"paexec.exe\")\n     or (InitiatingProcessFileName =~ \"wmiprvse.exe\" and FileName in~ (\"cmd.exe\", \"powershell.exe\"))\n     or (InitiatingProcessFileName =~ \"services.exe\" and FileName in~ (\"cmd.exe\", \"powershell.exe\"))\n| project Timestamp, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine",
        "read": "Commands under wmiprvse.exe or services.exe ran on behalf of a remote caller."
      },
      {
        "ctx": "Which internal hosts made network logons to this device?",
        "kql": "DeviceLogonEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where LogonType == \"Network\" and ActionType == \"LogonSuccess\" and RemoteIPType == \"Private\"\n| summarize Logons = count(), Last = max(Timestamp) by AccountName, RemoteDeviceName, RemoteIP\n| order by Last desc",
        "read": "The source device is where the attacker came from. Investigate it next."
      },
      {
        "ctx": "Where else did the account log on?",
        "kql": "DeviceLogonEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where AccountName =~ \"{{ACCOUNT}}\" and ActionType == \"LogonSuccess\"\n| summarize Logons = count(), LogonTypes = make_set(LogonType), First = min(Timestamp), Last = max(Timestamp)\n            by DeviceName\n| order by First asc",
        "read": "Ordering by first logon gives the path the attacker took through the network."
      }
    ],
    "fp": "IT admins and deployment tools use PsExec and WMI routinely. Check the account against your admin list."
  },
  {
    "id": "recon-cmds",
    "name": "Discovery commands: user, group and domain reconnaissance",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "low",
    "mitre": [
      "T1087.002",
      "T1482",
      "T1016"
    ],
    "summary": "A burst of whoami, net group, nltest and similar commands is typical of an attacker mapping the environment after first access.",
    "steps": [
      {
        "ctx": "Who ran many discovery commands in a short time?",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ProcessCommandLine has_any (\"whoami\", \"net group\", \"net localgroup\", \"nltest\", \"domain_trusts\",\n        \"dsquery\", \"adfind\", \"Get-ADUser\", \"Get-ADGroupMember\", \"quser\", \"systeminfo\", \"ipconfig /all\")\n| summarize Commands = make_set(ProcessCommandLine, 50), Count = count()\n            by DeviceName, AccountName, bin(Timestamp, 1h)\n| where Count >= 5\n| order by Count desc",
        "read": "Five or more different discovery commands within an hour from a normal user account is unusual. Check what ran just before."
      }
    ],
    "fp": "Helpdesk staff and login scripts run whoami and ipconfig. Filter known admin accounts."
  },
  {
    "id": "taskkill-multi",
    "name": "Stopping multiple processes using taskkill",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "medium",
    "mitre": [
      "T1489",
      "T1562.001"
    ],
    "playbook": true,
    "summary": "Something ran taskkill against several processes in a short time. Attackers do this to stop security tools, backup agents or databases before encryption. Decide whether the parent process and the killed processes are legitimate.",
    "steps": [
      {
        "ctx": "Who ran taskkill? (parent process, account, command lines, ±30 min of the alert)",
        "kql": "let AlertTime = toscalar(AlertInfo | where AlertId == \"{{ALERTID}}\" | summarize min(Timestamp));\nDeviceProcessEvents\n| where Timestamp between ((AlertTime - 30m) .. (AlertTime + 30m))\n| where DeviceName startswith \"{{DEVICE}}\" and FileName =~ \"taskkill.exe\"\n| project Timestamp, AccountDomain, AccountName, ProcessCommandLine,\n          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath,\n          InitiatingProcessParentFileName, InitiatingProcessSHA256, InitiatingProcessSignatureStatus\n| order by Timestamp asc",
        "read": "The query finds the alert time from the Alert ID, so fill in both Alert ID and Device. A <b>signed parent in Program Files</b> (an installer, updater or management agent) is usually benign. An <b>unsigned parent</b>, or one running from a user, Temp or ProgramData folder, or a script host (cmd, powershell, wscript, mshta), needs a closer look."
      },
      {
        "ctx": "Which processes were killed? (matches /PID values to process names)",
        "kql": "let AlertTime = toscalar(AlertInfo | where AlertId == \"{{ALERTID}}\" | summarize min(Timestamp));\nlet Kills = DeviceProcessEvents\n| where Timestamp between ((AlertTime - 30m) .. (AlertTime + 30m))\n| where DeviceName startswith \"{{DEVICE}}\" and FileName =~ \"taskkill.exe\"\n| extend KilledPid = extract_all(@\"(?i)/PID\\s+(\\d+)\", ProcessCommandLine)\n| mv-expand KilledPid to typeof(long)\n| project KillTime = Timestamp, KilledPid;\nDeviceProcessEvents\n| where Timestamp between ((AlertTime - 1d) .. (AlertTime + 30m))\n| where DeviceName startswith \"{{DEVICE}}\"\n| join kind=inner Kills on $left.ProcessId == $right.KilledPid\n| where Timestamp <= KillTime\n| summarize arg_max(Timestamp, *) by KilledPid\n| project KilledPid, KillTime, FileName, FolderPath, ProcessCommandLine, AccountName, StartedAt = Timestamp",
        "read": "PIDs get reused, so the query keeps the latest process with that PID that started before the kill. <b>Security, backup or database processes</b> (Defender, EDR agents, vss, sql, veeam, backup services) being killed is a strong ransomware signal. Browsers or the app's own helper processes usually mean an updater. If taskkill used <b>/IM name</b> instead of /PID, nothing comes back here; read the names in step 1's command lines."
      },
      {
        "ctx": "What else ran on the device around the alert? (scripts, service and backup changes, ±30 min)",
        "kql": "let AlertTime = toscalar(AlertInfo | where AlertId == \"{{ALERTID}}\" | summarize min(Timestamp));\nDeviceProcessEvents\n| where Timestamp between ((AlertTime - 30m) .. (AlertTime + 30m))\n| where DeviceName startswith \"{{DEVICE}}\"\n| where InitiatingProcessFileName in~ (\"cmd.exe\", \"powershell.exe\", \"pwsh.exe\", \"wscript.exe\", \"cscript.exe\", \"mshta.exe\", \"rundll32.exe\")\n   or FileName in~ (\"vssadmin.exe\", \"wbadmin.exe\", \"bcdedit.exe\", \"sc.exe\", \"net.exe\", \"net1.exe\", \"wmic.exe\")\n| project Timestamp, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine\n| order by Timestamp asc",
        "read": "<b>vssadmin delete shadows</b>, <b>wbadmin delete</b>, <b>bcdedit recoveryenabled no</b> or <b>sc stop / net stop</b> on security or backup services next to the kills means treat it as ransomware: isolate the device. Only taskkill from an installer with nothing else around it is usually an update."
      },
      {
        "ctx": "Is this normal for this parent process? (30 days, all devices)",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{BASELINE}}) and FileName =~ \"taskkill.exe\"\n| summarize Runs = count(), Devices = dcount(DeviceName), DeviceList = make_set(DeviceName, 10),\n            First = min(Timestamp), Last = max(Timestamp)\n            by InitiatingProcessFileName, InitiatingProcessFolderPath\n| order by Runs desc",
        "read": "A parent that runs taskkill on many devices every week is a deployed tool or updater. A parent seen only on <b>this one device</b>, for the first time, is the one to investigate."
      }
    ],
    "fp": "Software installers and updaters (browsers, Office, VPN and printer clients), RMM and patching agents, and login or kiosk scripts routinely kill several processes before replacing files."
  },
  {
    "id": "ssh-bruteforce",
    "name": "SSH brute force against a Linux host",
    "cat": "Endpoint",
    "src": "Linux Syslog (Sentinel)",
    "sev": "medium",
    "mitre": [
      "T1110",
      "T1110.001",
      "T1021.004",
      "T1078"
    ],
    "playbook": true,
    "summary": "Many failed SSH logins against a Linux host. Decide whether any brute-force source, unexpected user or unexpected IP actually got in, and whether a real account was targeted.",
    "steps": [
      {
        "ctx": "Did any brute-force source, or any unexpected user or IP, log in over SSH? (look-back window)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ProcessName == \"sshd\" and SyslogMessage has \"Accepted\"\n| extend SrcIP = extract(@\"from (\\d+\\.\\d+\\.\\d+\\.\\d+)\", 1, SyslogMessage),\n         User = extract(@\"for (\\S+) from\", 1, SyslogMessage),\n         Method = extract(@\"Accepted (\\S+)\", 1, SyslogMessage)\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Computer, HostIP, Method, User, SrcIP\n| order by n desc",
        "read": "Any <b>Accepted</b> row from an IP that also appears in the failed attempts means the brute force <b>succeeded</b>: isolate the host and reset that account. <b>publickey</b> logins from known admin IPs are normal; <b>password</b> logins from internet IPs are not."
      },
      {
        "ctx": "Which accounts were targeted? (failed SSH attempts by username)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ProcessName == \"sshd\" and SyslogMessage has_any (\"Failed password\", \"Invalid user\", \"authentication failure\")\n| extend SrcIP = extract(@\"(?:from|rhost=)\\s?(\\d+\\.\\d+\\.\\d+\\.\\d+)\", 1, SyslogMessage),\n         User = coalesce(extract(@\"Invalid user (\\S+)\", 1, SyslogMessage), extract(@\"Failed password for (?:invalid user )?(\\S+)\", 1, SyslogMessage))\n| summarize Attempts = count(), IPs = dcount(SrcIP) by Computer, User\n| order by Attempts desc\n| take 25",
        "read": "Many different usernames (root, admin, test, oracle…) from many IPs is generic dictionary guessing. Many attempts on <b>one real account</b> is a targeted attack; check that account in step 3. Set the look-back to cover the incident window (e.g. 2d)."
      },
      {
        "ctx": "Outcome for the main attacking range and the valid admin account",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ProcessName == \"sshd\"\n| where SyslogMessage has \"{{ACCOUNT}}\" or SyslogMessage has \"{{IP}}\"\n| extend SrcIP = extract(@\"(\\d+\\.\\d+\\.\\d+\\.\\d+)\", 1, SyslogMessage),\n         Type = case(SyslogMessage has \"Accepted\", \"Accepted\",\n                     SyslogMessage has \"Failed password\", \"FailedPassword\",\n                     SyslogMessage has \"Invalid user\", \"InvalidUser\",\n                     SyslogMessage has \"Disconnected\" or SyslogMessage has \"Connection closed\", \"Closed\",\n                     \"Other\")\n| summarize n = count()\n    by Bucket = iff(SrcIP startswith \"{{IP}}\", strcat(extract(@\"^(\\d+\\.\\d+\\.\\d+)\\.\", 1, SrcIP), \".0/24\"), SrcIP),\n       HasAccount = SyslogMessage has \"{{ACCOUNT}}\", Type\n| order by n desc\n| take 20",
        "read": "Put the attacking IP or range prefix (e.g. <b>203.0.113.</b>) in <b>IP address</b> and the real admin account in <b>Account name</b>. Rows are bucketed to the range's /24. <b>Accepted</b> with HasAccount true means the admin account logged in during the attack: confirm it was the real admin."
      },
      {
        "ctx": "Auth sessions opened: anything unexpected in sshd, sudo, CRON or runuser? (look-back window)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Facility in (\"auth\", \"authpriv\")\n| where SyslogMessage has_any (\"Accepted password\", \"Accepted publickey\", \"session opened for user\")\n| extend SrcIP = extract(@\"from (\\d+\\.\\d+\\.\\d+\\.\\d+)\", 1, SyslogMessage),\n         User = extract(@\"(?:for|user) (\\S+)\", 1, SyslogMessage),\n         Method = extract(@\"Accepted (\\S+)\", 1, SyslogMessage)\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Computer, HostIP, ProcessName, Method, User, SrcIP\n| order by n desc\n| take 40",
        "read": "Expect CRON and runuser sessions for service accounts. Look for <b>sudo</b> or <b>session opened</b> for users who shouldn't be on this host, or new SrcIPs. The original check used 3 days: type <b>3d</b> in Look-back window to match."
      },
      {
        "ctx": "Outcome per flagged source IP or range (any success?)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ProcessName == \"sshd\"\n| extend SrcIP = extract(@\"(\\d+\\.\\d+\\.\\d+\\.\\d+)\", 1, SyslogMessage)\n| where SrcIP startswith \"{{IP}}\"\n| extend Type = case(SyslogMessage has \"Accepted\", \"Accepted\", SyslogMessage has \"Failed password\", \"FailedPassword\", SyslogMessage has \"Invalid user\", \"InvalidUser\", \"Other\")\n| summarize n = count() by SrcIP, Type\n| order by SrcIP asc, n desc",
        "read": "Put every flagged IP or range prefix in <b>IP address</b>, comma-separated (e.g. <b>203.0.113., 198.51.100.</b>). Each source should show only FailedPassword / InvalidUser; any <b>Accepted</b> row means that source got in."
      }
    ],
    "fp": "Internet-facing SSH gets constant dictionary scanning; failures alone with no Accepted rows are usually noise. Vulnerability scanners and configuration tools (Ansible, backup jobs) also log many SSH sessions from known IPs."
  },
  {
    "id": "spray",
    "name": "Password spray against Entra ID",
    "cat": "Identity",
    "src": "Entra ID",
    "sev": "medium",
    "mitre": [
      "T1110.003"
    ],
    "summary": "One source tries a few passwords against many accounts. The danger is the account that finally succeeds.",
    "steps": [
      {
        "ctx": "Which IPs failed against many accounts?",
        "kql": "EntraIdSignInEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ErrorCode == 50126\n| summarize Accounts = dcount(AccountUpn), Attempts = count(), Countries = make_set(Country)\n            by IPAddress\n| where Accounts >= 10\n| order by Accounts desc",
        "read": "Ten or more accounts from one IP is the spray signature. Lower the threshold for small tenants."
      },
      {
        "ctx": "Did any account then sign in successfully from a spraying IP?",
        "kql": "let SprayIPs = EntraIdSignInEvents\n    | where Timestamp > ago({{LOOKBACK}}) and ErrorCode == 50126\n    | summarize Accounts = dcount(AccountUpn) by IPAddress\n    | where Accounts >= 10\n    | project IPAddress;\nEntraIdSignInEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ErrorCode == 0 and IPAddress in (SprayIPs)\n| project Timestamp, AccountUpn, IPAddress, Country, Application, AuthenticationRequirement",
        "read": "Any row is a compromised password. If AuthenticationRequirement is singleFactorAuthentication, the attacker is already in."
      },
      {
        "ctx": "Sentinel version of the spray check",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ResultType == \"50126\"\n| summarize Accounts = dcount(UserPrincipalName), Attempts = count(),\n            Country = take_any(tostring(LocationDetails.countryOrRegion))\n            by IPAddress\n| where Accounts >= 10\n| order by Accounts desc",
        "read": "Use this one if your sign-in data lives in a Sentinel workspace."
      }
    ],
    "fp": "A misconfigured app or shared NAT address can fail for many users at once. Check the Application column."
  },
  {
    "id": "mfa-fatigue",
    "name": "MFA fatigue: repeated MFA denials",
    "cat": "Identity",
    "src": "Entra ID",
    "sev": "medium",
    "mitre": [
      "T1621"
    ],
    "summary": "An attacker with the password keeps pushing MFA prompts hoping the user approves one.",
    "steps": [
      {
        "ctx": "How many MFA failures did the user get, and from where?",
        "kql": "EntraIdSignInEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where AccountUpn =~ \"{{UPN}}\"\n| where ErrorCode in (500121, 50074)\n| summarize Failures = count(), IPs = make_set(IPAddress), Countries = make_set(Country)\n            by bin(Timestamp, 1h)\n| order by Timestamp desc",
        "read": "Many failures in one hour from an IP the user does not use means the password is known to an attacker. Reset it even if no prompt was approved."
      },
      {
        "ctx": "Was a prompt eventually approved?",
        "kql": "EntraIdSignInEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where AccountUpn =~ \"{{UPN}}\"\n| where ErrorCode == 0 and AuthenticationRequirement == \"multiFactorAuthentication\"\n| project Timestamp, IPAddress, Country, City, Application, UserAgent\n| order by Timestamp desc",
        "read": "A success from the same IP as the failures means the user approved the attacker's prompt. Revoke sessions and reset now."
      }
    ],
    "fp": "A user with a broken authenticator app or travelling between time zones can fail MFA repeatedly. Ask them."
  },
  {
    "id": "travel",
    "name": "Atypical travel or sign-in from a new country",
    "cat": "Identity",
    "src": "Entra ID",
    "sev": "medium",
    "mitre": [
      "T1078.004"
    ],
    "summary": "The user signed in from two distant places too close together, or from a country they have never used.",
    "steps": [
      {
        "ctx": "Where did the user's country change between consecutive sign-ins?",
        "kql": "EntraIdSignInEvents\n| where Timestamp > ago({{BASELINE}})\n| where AccountUpn =~ \"{{UPN}}\" and ErrorCode == 0\n| project Timestamp, Country, City, IPAddress, Application, UserAgent\n| order by Timestamp asc\n| extend PrevCountry = prev(Country), PrevTime = prev(Timestamp)\n| where isnotempty(PrevCountry) and Country != PrevCountry\n| extend HoursBetween = datetime_diff('hour', Timestamp, PrevTime)",
        "read": "A country change within a few hours that no flight could explain is the impossible-travel case. Check whether one side is a VPN or cloud provider IP."
      },
      {
        "ctx": "Is the unusual IP used by other users?",
        "kql": "EntraIdSignInEvents\n| where Timestamp > ago({{BASELINE}})\n| where IPAddress == \"{{IP}}\"\n| summarize Users = dcount(AccountUpn), SampleUsers = make_set(AccountUpn, 15),\n            Success = countif(ErrorCode == 0), Failed = countif(ErrorCode != 0)",
        "read": "Many colleagues on the same IP suggests a corporate VPN or partner network. A single user suggests personal travel or an attacker."
      }
    ],
    "fp": "VPNs, mobile carriers and cloud-hosted desktops commonly cause false impossible-travel alerts."
  },
  {
    "id": "onprem-bf",
    "name": "On-premises brute force against Active Directory",
    "cat": "Identity",
    "src": "Defender for Identity",
    "sev": "medium",
    "mitre": [
      "T1110"
    ],
    "summary": "Many failed Kerberos or NTLM logons against domain accounts, seen by Defender for Identity sensors on domain controllers.",
    "steps": [
      {
        "ctx": "Which sources failed most against which accounts?",
        "kql": "IdentityLogonEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ActionType == \"LogonFailed\"\n| summarize Failures = count(), Accounts = dcount(AccountName), SampleAccounts = make_set(AccountName, 20),\n            Reasons = make_set(FailureReason), Protocols = make_set(Protocol)\n            by DeviceName, IPAddress\n| where Failures > 20\n| order by Failures desc",
        "read": "Many accounts from one device is spraying. One account from many devices is usually a stale password or a lockout loop."
      },
      {
        "ctx": "Did the same source then log on successfully?",
        "kql": "IdentityLogonEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where IPAddress == \"{{IP}}\" or DeviceName startswith \"{{DEVICE}}\"\n| summarize Success = countif(ActionType == \"LogonSuccess\"), Failed = countif(ActionType == \"LogonFailed\"),\n            Accounts = make_set(AccountName, 25), LogonTypes = make_set(LogonType)\n            by DeviceName, IPAddress",
        "read": "A success after many failures from the same source should be treated as a compromised account."
      }
    ],
    "fp": "Disconnected drive mappings and services running with old passwords cause steady failures."
  },
  {
    "id": "ldap-recon",
    "name": "Account and group reconnaissance (LDAP / SAMR)",
    "cat": "Identity",
    "src": "Defender for Identity",
    "sev": "medium",
    "mitre": [
      "T1087.002",
      "T1069.002"
    ],
    "summary": "A device queried Active Directory for users, groups or admins at a volume or pattern that suggests mapping for privilege escalation.",
    "steps": [
      {
        "ctx": "Which devices and accounts are querying AD the most?",
        "kql": "IdentityQueryEvents\n| where Timestamp > ago({{LOOKBACK}})\n| summarize Queries = count(), Types = make_set(QueryType), Targets = make_set(QueryTarget, 25)\n            by DeviceName, AccountName\n| order by Queries desc",
        "read": "Workstations should not query hundreds of AD objects. Servers like Exchange and identity sync tools do."
      },
      {
        "ctx": "Who looked up the privileged groups?",
        "kql": "IdentityQueryEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where QueryTarget has_any (\"Domain Admins\", \"Enterprise Admins\", \"Schema Admins\", \"Administrators\")\n| project Timestamp, DeviceName, AccountName, QueryType, QueryTarget, Protocol",
        "read": "Look up the device in the endpoint entries to see which process made the queries."
      }
    ],
    "fp": "Vulnerability scanners, IAM tools and BloodHound runs by your own red team match this pattern."
  },
  {
    "id": "priv-group",
    "name": "Account added to a privileged group or role",
    "cat": "Identity",
    "src": "Defender for Identity / Entra ID",
    "sev": "high",
    "mitre": [
      "T1098",
      "T1098.003"
    ],
    "summary": "Someone gained admin rights on-premises or in Entra ID. Confirm who added whom and whether it was approved.",
    "steps": [
      {
        "ctx": "On-premises: who was added to admin groups?",
        "kql": "IdentityDirectoryEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ActionType == \"Group Membership changed\"\n| extend ToGroup = tostring(AdditionalFields[\"TO.GROUP\"]), FromGroup = tostring(AdditionalFields[\"FROM.GROUP\"])\n| where ToGroup in~ (\"Domain Admins\", \"Enterprise Admins\", \"Schema Admins\", \"Administrators\")\n     or FromGroup in~ (\"Domain Admins\", \"Enterprise Admins\", \"Schema Admins\", \"Administrators\")\n| project Timestamp, ToGroup, FromGroup, TargetAccountDisplayName, AccountName, DeviceName",
        "read": "AccountName is who made the change. Confirm there is a change ticket."
      },
      {
        "ctx": "Entra ID: who was given a directory role?",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where OperationName in (\"Add member to role\", \"Add eligible member to role\")\n| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),\n         Target = tostring(TargetResources[0].userPrincipalName),\n         Role = tostring(TargetResources[0].modifiedProperties[1].newValue)\n| project TimeGenerated, OperationName, Result, Actor, Target, Role",
        "read": "If Role is empty, expand TargetResources: the role name position varies by operation."
      }
    ],
    "fp": "Privileged Identity Management activations and scheduled admin onboarding are expected."
  },
  {
    "id": "phish-delivered",
    "name": "Phishing email delivered or removed after delivery",
    "cat": "Email",
    "src": "Defender for Office 365",
    "sev": "medium",
    "mitre": [
      "T1566"
    ],
    "summary": "A phishing email reached mailboxes, or was pulled back by zero-hour auto purge (ZAP). Find every recipient and where the message is now.",
    "steps": [
      {
        "ctx": "Who received it, and where is it now?",
        "kql": "EmailEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where NetworkMessageId == \"{{MSGID}}\" or SenderFromAddress =~ \"{{SENDER}}\"\n| project Timestamp, RecipientEmailAddress, Subject, SenderFromAddress, SenderIPv4,\n          DeliveryAction, DeliveryLocation, LatestDeliveryLocation, ThreatTypes, AuthenticationDetails",
        "read": "LatestDeliveryLocation shows where the email is now. Inbox means it is still reachable by the user."
      },
      {
        "ctx": "Was it removed after delivery?",
        "kql": "EmailPostDeliveryEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where NetworkMessageId == \"{{MSGID}}\"\n| project Timestamp, RecipientEmailAddress, Action, ActionType, ActionTrigger, ActionResult, DeliveryLocation",
        "read": "ZAP or admin removal is good, but a user may have clicked between delivery and removal. Run the malicious link entry next."
      },
      {
        "ctx": "Did the same sending domain hit other people?",
        "kql": "EmailEvents\n| where Timestamp > ago({{BASELINE}})\n| where SenderFromDomain =~ \"{{DOMAIN}}\"\n| summarize Emails = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10),\n            Delivered = countif(DeliveryAction == \"Delivered\")\n            by SenderFromAddress",
        "read": "Use this to size the campaign and decide whether to block the domain in the Tenant Allow/Block List."
      }
    ],
    "fp": "Marketing and newsletter platforms sometimes get phishing verdicts. Check AuthenticationDetails for DMARC pass."
  },
  {
    "id": "url-click",
    "name": "User clicked a malicious link",
    "cat": "Email",
    "src": "Defender for Office 365",
    "sev": "high",
    "mitre": [
      "T1204.001",
      "T1566.002"
    ],
    "summary": "Safe Links recorded a click on a URL now known to be malicious. Check whether the user got through, whether the device reached the site, and whether credentials were used afterwards.",
    "steps": [
      {
        "ctx": "Who clicked, and did Safe Links let them through?",
        "kql": "UrlClickEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where AccountUpn =~ \"{{UPN}}\" or Url has \"{{DOMAIN}}\"\n| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, ThreatTypes, Workload, IPAddress, NetworkMessageId",
        "read": "<b>ClickAllowed</b> or IsClickedThrough = true means the user reached the page."
      },
      {
        "ctx": "Did any device connect to the domain?",
        "kql": "DeviceNetworkEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where RemoteUrl has \"{{DOMAIN}}\"\n| summarize Connections = count(), First = min(Timestamp), Last = max(Timestamp)\n            by DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName",
        "read": "A browser connecting is expected after a click. Any other process connecting suggests a payload ran."
      },
      {
        "ctx": "Did the user's account sign in from somewhere new after the click?",
        "kql": "EntraIdSignInEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where AccountUpn =~ \"{{UPN}}\"\n| project Timestamp, ErrorCode, IPAddress, Country, City, Application, AuthenticationRequirement, UserAgent\n| order by Timestamp desc",
        "read": "A credential-phishing page is followed by sign-ins from the attacker's IP, often minutes later. Reset the password and revoke sessions if you see one."
      }
    ],
    "fp": "Security awareness simulations produce real clicks on test URLs. Check the domain against your simulation vendor."
  },
  {
    "id": "attachment",
    "name": "Malicious attachment delivered or opened",
    "cat": "Email",
    "src": "Defender for Office 365 / Endpoint",
    "sev": "high",
    "mitre": [
      "T1566.001"
    ],
    "summary": "An email attachment was later found to be malicious. Find the recipients, then check whether anyone saved or opened it.",
    "steps": [
      {
        "ctx": "Who received the attachment, and where is it now?",
        "kql": "EmailAttachmentInfo\n| where Timestamp > ago({{LOOKBACK}})\n| where SHA256 == \"{{SHA256}}\" or FileName =~ \"{{FILENAME}}\"\n| join kind=inner (\n    EmailEvents\n    | where Timestamp > ago({{LOOKBACK}})\n    | project NetworkMessageId, RecipientEmailAddress, Subject, DeliveryAction, LatestDeliveryLocation\n  ) on NetworkMessageId, RecipientEmailAddress\n| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType,\n          ThreatTypes, DeliveryAction, LatestDeliveryLocation",
        "read": "Purge any copies still in an Inbox."
      },
      {
        "ctx": "Was it saved or opened on a device?",
        "kql": "DeviceFileEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where SHA256 == \"{{SHA256}}\" or FileName =~ \"{{FILENAME}}\"\n| project Timestamp, DeviceName, ActionType, FolderPath, FileName, SHA1, InitiatingProcessFileName",
        "read": "SHA256 is often empty in device tables, which is why the file name is also matched. Take the SHA1 from here into the antivirus entry to check execution."
      }
    ],
    "fp": "Encrypted or password-protected business files sometimes get suspicious verdicts. Confirm with the sender out-of-band."
  },
  {
    "id": "inbox-rule",
    "name": "Suspicious inbox rule or mail forwarding",
    "cat": "Cloud apps",
    "src": "Defender for Cloud Apps",
    "sev": "high",
    "mitre": [
      "T1564.008",
      "T1114.003"
    ],
    "summary": "A rule forwards, deletes or hides email. Business email compromise often uses this to intercept invoices and hide replies.",
    "steps": [
      {
        "ctx": "Which inbox rules or forwarding settings were created or changed?",
        "kql": "CloudAppEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ActionType in (\"New-InboxRule\", \"Set-InboxRule\", \"UpdateInboxRules\", \"Set-Mailbox\")\n| extend User = tostring(RawEventData.UserId), Params = tostring(RawEventData.Parameters)\n| where Params has_any (\"ForwardTo\", \"RedirectTo\", \"ForwardingSmtpAddress\", \"DeleteMessage\", \"MoveToFolder\", \"MarkAsRead\")\n| project Timestamp, User, ActionType, IPAddress, CountryCode, Isp, Params",
        "read": "Rules that move mail with words like invoice, payment or the CFO's name into RSS Feeds or Archive are a classic compromise sign."
      },
      {
        "ctx": "Was the session that created the rule unusual for the user?",
        "kql": "CloudAppEvents\n| where Timestamp > ago({{BASELINE}})\n| where tostring(RawEventData.UserId) =~ \"{{UPN}}\"\n| summarize Events = count(), Actions = make_set(ActionType, 20), First = min(Timestamp), Last = max(Timestamp)\n            by IPAddress, CountryCode, Isp, IsAnonymousProxy\n| order by First desc",
        "read": "If the rule's IP first appears around the rule creation time, treat the mailbox as compromised."
      }
    ],
    "fp": "Users legitimately forward to a personal address or set up assistants. Check against your external forwarding policy."
  },
  {
    "id": "mass-download",
    "name": "Mass download from SharePoint or OneDrive",
    "cat": "Cloud apps",
    "src": "Defender for Cloud Apps",
    "sev": "medium",
    "mitre": [
      "T1530",
      "T1567"
    ],
    "summary": "A user downloaded an unusual number of files in a short time, which can mean data theft by an insider or an attacker using a stolen session.",
    "steps": [
      {
        "ctx": "Who downloaded the most files per hour?",
        "kql": "CloudAppEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ActionType in (\"FileDownloaded\", \"FileSyncDownloadedFull\")\n| summarize Files = dcount(ObjectName), IPs = make_set(IPAddress, 5)\n            by AccountDisplayName, AccountObjectId, bin(Timestamp, 1h)\n| where Files > 100\n| order by Files desc",
        "read": "Compare with the user's normal hourly volume. Departing employees and new devices syncing a library both show up here."
      },
      {
        "ctx": "What exactly did the user take?",
        "kql": "CloudAppEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ActionType in (\"FileDownloaded\", \"FileSyncDownloadedFull\")\n| where tostring(RawEventData.UserId) =~ \"{{UPN}}\"\n| project Timestamp, ObjectName, IPAddress, CountryCode, UserAgent, Site = tostring(RawEventData.SiteUrl)\n| order by Timestamp desc",
        "read": "Check sensitivity: HR, finance and source code folders raise the priority."
      }
    ],
    "fp": "OneDrive sync on a new laptop downloads everything at once."
  },
  {
    "id": "oauth-consent",
    "name": "Risky OAuth app consent",
    "cat": "Cloud apps",
    "src": "Defender for Cloud Apps",
    "sev": "medium",
    "mitre": [
      "T1528"
    ],
    "summary": "A user granted an app access to their data. Consent phishing uses this to read mail and files without needing the password.",
    "steps": [
      {
        "ctx": "Who consented to which apps?",
        "kql": "CloudAppEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where ActionType == \"Consent to application.\"\n| project Timestamp, AccountDisplayName, ObjectName, IPAddress, CountryCode, RawEventData",
        "read": "RawEventData lists the permissions granted. Mail.Read, Files.ReadWrite.All and offline_access together are high risk."
      },
      {
        "ctx": "What has the app done since consent?",
        "kql": "CloudAppEvents\n| where Timestamp > ago({{BASELINE}})\n| where OAuthAppId == \"{{APPID}}\"\n| summarize Events = count(), Users = dcount(AccountObjectId), First = min(Timestamp), Last = max(Timestamp)\n            by ActionType\n| order by Events desc",
        "read": "Mass mail reads (MailItemsAccessed) or file access across many users means the app is harvesting data. Revoke the consent."
      }
    ],
    "fp": "Popular productivity add-ins request broad permissions. Check publisher verification in Entra ID."
  },
  {
    "id": "anon-proxy",
    "name": "Activity from an anonymous proxy or TOR",
    "cat": "Cloud apps",
    "src": "Defender for Cloud Apps",
    "sev": "medium",
    "mitre": [
      "T1090.003"
    ],
    "summary": "Cloud app activity came from an IP known as an anonymous proxy. Attackers use these to hide their location.",
    "steps": [
      {
        "ctx": "Which accounts were active through anonymous proxies, and doing what?",
        "kql": "CloudAppEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where IsAnonymousProxy == true\n| summarize Events = count(), Actions = make_set(ActionType, 20), Apps = make_set(Application),\n            First = min(Timestamp), Last = max(Timestamp)\n            by AccountDisplayName, IPAddress, CountryCode\n| order by Events desc",
        "read": "Sign-in only is lower risk than mail access, file downloads or inbox rule changes from a proxy."
      }
    ],
    "fp": "Privacy-focused users and some consumer VPNs are flagged as anonymous proxies."
  },
  {
    "id": "fw-ioc-exfil",
    "name": "Multi-stage incident: execution & exfiltration (firewall IoC / first-seen IP)",
    "cat": "Network",
    "src": "Sentinel (CommonSecurityLog) + Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1041",
      "T1071",
      "T1048"
    ],
    "playbook": true,
    "summary": "Firewall IoC and first-seen external IP alerts grouped into one incident. Work out which hosts talked to the IP, how much data left, whether the IoC is really malicious (e.g. a public resolver) and which process made the connection.",
    "steps": [
      {
        "ctx": "Which hosts connected to the IP, and how much data left the network?",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where DestinationIP == \"{{IP}}\" or SourceIP == \"{{IP}}\"\n| summarize Connections = count(), BytesOut = sum(SentBytes), BytesIn = sum(ReceivedBytes),\n            Ports = make_set(DestinationPort), Actions = make_set(DeviceAction),\n            First = min(TimeGenerated), Last = max(TimeGenerated)\n  by SourceIP, DestinationIP, DeviceVendor, DeviceProduct\n| order by BytesOut desc",
        "read": "Large <b>BytesOut</b> with small BytesIn from one host is the exfiltration pattern. Mostly inbound bytes means downloads (updates, CDN)."
      },
      {
        "ctx": "What is the IoC traffic? (DNS / DoT / ping to a public resolver is usually benign)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where DestinationIP == \"{{IP}}\"\n| summarize Connections = count(), BytesOut = sum(SentBytes), Ports = make_set(DestinationPort),\n            Actions = make_set(DeviceAction)\n  by SourceIP, ApplicationProtocol\n| order by Connections desc",
        "read": "Ports 53, 853 or ICMP to a resolver such as 1.1.1.1 from many hosts is normal DNS use; the threat-intel match is the problem, not the traffic (see the next step)."
      },
      {
        "ctx": "Which threat-intel indicator flags the IP? (source, confidence, expiry)",
        "kql": "ThreatIntelligenceIndicator\n| where NetworkIP == \"{{IP}}\" or NetworkDestinationIP == \"{{IP}}\"\n| project TimeGenerated, SourceSystem, Description, ThreatType, ConfidenceScore, ExpirationDateTime, Active, IndicatorId\n| order by TimeGenerated desc\n// Newer TI schema: ThreatIntelIndicators | where ObservableValue == \"{{IP}}\"",
        "read": "Use the SourceSystem and IndicatorId to ask for the indicator to be removed or excluded when it flags a well-known benign service."
      },
      {
        "ctx": "Which endpoint process and account connected to the IP? (execution stage)",
        "kql": "DeviceNetworkEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where RemoteIP == \"{{IP}}\"\n| summarize Conns = count() by DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName, RemotePort",
        "read": "A browser or signed updater is usually benign. Script hosts (powershell, wscript, mshta), unsigned binaries in user or temp folders, or SYSTEM-level tools making the connection need escalation."
      }
    ],
    "fp": "Public DNS resolvers (1.1.1.1, 8.8.8.8) and CDN ranges on low-quality threat feeds; vendor update agents to newly seen CDN nodes."
  },
  {
    "id": "first-seen-ext-ip",
    "name": "First-seen external IP (firewall connections)",
    "cat": "Network",
    "src": "Sentinel (CommonSecurityLog / Fortigate) + Defender for Endpoint",
    "sev": "medium",
    "mitre": [
      "T1071.001"
    ],
    "playbook": true,
    "summary": "An internal host connected to an external IP not seen before. Identify the hosts, what the sessions were (Fortigate app / category / hostname) and the process behind them.",
    "steps": [
      {
        "ctx": "Per-host connection summary to the IP (bytes, ports, actions, apps)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{BASELINE}})\n| where DestinationIP == \"{{IP}}\" or SourceIP == \"{{IP}}\"\n| summarize Connections = count(), BytesOut = sum(SentBytes), BytesIn = sum(ReceivedBytes), Ports = make_set(DestinationPort),\n            Actions = make_set(DeviceAction), Apps = make_set(ApplicationProtocol), Hosts = make_set(DestinationHostName),\n            First = min(TimeGenerated), Last = max(TimeGenerated)\n  by SourceIP, DestinationIP, DeviceProduct\n| order by Connections desc",
        "read": "Mostly inbound bytes over 443 with normal close/accept actions points to downloads. Note the internal SourceIPs for the device mapping in step 3."
      },
      {
        "ctx": "Fortigate application, category, hostname and user for the sessions",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{BASELINE}})\n| where DestinationIP == \"{{IP}}\"\n| extend app = extract(@\"(?:^|;)app=([^;]+)\", 1, AdditionalExtensions), appcat = extract(@\"appcat=([^;]+)\", 1, AdditionalExtensions),\n         hostname = extract(@\"hostname=([^;]+)\", 1, AdditionalExtensions), catdesc = extract(@\"catdesc=([^;]+)\", 1, AdditionalExtensions),\n         srcname = extract(@\"srcname=([^;]+)\", 1, AdditionalExtensions), user = extract(@\"(?:^|;)user=([^;]+)\", 1, AdditionalExtensions)\n| summarize n = count() by SourceIP, app, appcat, hostname, catdesc, srcname, user, RequestURL, DestinationHostName, Activity\n| order by n desc",
        "read": "<b>appcat=unscanned</b> with no hostname is encrypted traffic the firewall didn't inspect; the process in step 3 is then the best evidence."
      },
      {
        "ctx": "Process attribution in MDE and internal IP to device mapping",
        "kql": "union\n(DeviceNetworkEvents | where Timestamp > ago({{LOOKBACK}}) | where RemoteIP == \"{{IP}}\"\n | summarize n = count() by Src = \"MDE_Net\", DeviceName, Detail = strcat(InitiatingProcessFileName, \" | \", InitiatingProcessAccountName, \" | \", RemoteUrl)),\n(DeviceNetworkInfo | where Timestamp > ago({{LOOKBACK}}) | mv-expand ip = parse_json(IPAddresses)\n | where tostring(ip.IPAddress) in (\"{{INTIP}}\")\n | summarize n = count() by Src = \"IPmap\", DeviceName, Detail = tostring(ip.IPAddress))\n| order by Src, n desc",
        "read": "Put the internal source IPs from step 1 in <b>Internal IP</b> (comma-separated). IPmap rows name the devices; MDE_Net rows name the process and account that made the connection."
      }
    ],
    "fp": "Vendor update agents and CDNs rotate to new IPs constantly; check the client playbook's Known benign list before escalating."
  },
  {
    "id": "ntds-vss-dump",
    "name": "AD – VSS shadow copy / NTDS.dit dump attempt",
    "cat": "Endpoint",
    "src": "Sentinel analytics + Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1003.003",
      "T1006"
    ],
    "playbook": true,
    "summary": "A generic NTDS / shadow-copy rule matched a process. Get the full command line and parent chain to tell a file-name keyword match or database maintenance (esentutl on SRUDB.dat) from real credential dumping.",
    "steps": [
      {
        "ctx": "Full command lines of the flagged processes (which keyword triggered the rule?)",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName in~ (\"{{FILENAME}}\")\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName\n| order by Timestamp asc",
        "read": "Put the flagged hosts in <b>Device name</b> and the flagged processes (e.g. protocolhandler.exe, EXCEL.EXE, Acrobat.exe) in <b>File name</b>. Set the look-back to cover the alert (e.g. 1d). An Office or PDF process whose command line merely contains a file name like <i>ntds</i> is a keyword false positive."
      },
      {
        "ctx": "esentutl command lines and parent chain (maintenance vs. credential dumping)",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName =~ \"esentutl.exe\" or InitiatingProcessFileName =~ \"esentutl.exe\"\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,\n          InitiatingProcessFileName, InitiatingProcessCommandLine,\n          InitiatingProcessParentFileName, InitiatingProcessFolderPath\n| order by Timestamp asc",
        "read": "<b>esentutl /p</b> or <b>/y</b> on <b>SRUDB.dat</b> run as SYSTEM by a Windows service is database maintenance. <b>/y</b> copying <b>ntds.dit</b> or a SYSTEM hive to a writable folder, or a cmd/powershell parent, is credential dumping: escalate."
      }
    ],
    "fp": "Document names containing 'ntds' or 'vss'; Windows SRUM database repair by esentutl running as SYSTEM."
  },
  {
    "id": "sentinel-budget-breach",
    "name": "Sentinel ingestion budget breach",
    "cat": "SIEM health",
    "src": "Microsoft Sentinel (Usage)",
    "sev": "low",
    "mitre": [],
    "playbook": true,
    "summary": "Daily billable ingestion went over the workspace budget. Confirm the size of the overage and which tables drove it.",
    "steps": [
      {
        "ctx": "Daily billable ingestion vs. budget (last 24 hours)",
        "kql": "Usage\n| where TimeGenerated > ago(1d)\n| where IsBillable == true\n| summarize TotalGB = round(sum(Quantity) / 1024, 2)\n| extend BudgetGB = 30    // set to the workspace's daily budget\n| extend OverBudgetGB = round(TotalGB - BudgetGB, 2),\n         BudgetUsedPct = round(TotalGB / BudgetGB * 100, 1)",
        "read": "Change <b>BudgetGB</b> to the client's daily budget. A small overage on one day is usually a spike; repeated overages mean the budget or collection needs review."
      },
      {
        "ctx": "Top contributing tables (last 24 hours)",
        "kql": "Usage\n| where TimeGenerated > ago(1d)\n| where IsBillable == true\n| summarize TodayGB = round(sum(Quantity) / 1024, 3) by DataType\n| order by TodayGB desc\n| take 10",
        "read": "Check the top table in the ingestion-anomaly entry to see whether it spiked or has always been large."
      }
    ],
    "fp": "Month-end jobs, new connectors and incident-driven verbose logging all raise ingestion legitimately."
  },
  {
    "id": "sentinel-ingestion-anomaly",
    "name": "Sentinel ingestion anomaly / single-table spike",
    "cat": "SIEM health",
    "src": "Microsoft Sentinel (Usage, Anomalies, ThreatIntelIndicators)",
    "sev": "low",
    "mitre": [],
    "playbook": true,
    "summary": "A table's ingestion jumped above its 14-day baseline (Z-score or spike-ratio rule). Find which tables spiked, by how much, and what caused it.",
    "steps": [
      {
        "ctx": "Z-score per table vs. 14-day baseline (which tables spiked?)",
        "kql": "let Baseline = Usage\n| where TimeGenerated between (ago(15d) .. ago(1d))\n| where IsBillable == true\n| summarize DailyGB = sum(Quantity) / 1024 by DataType, bin(TimeGenerated, 1d)\n| summarize AvgGB = avg(DailyGB), StdGB = stdev(DailyGB) by DataType;\nUsage\n| where TimeGenerated > ago(1d)\n| where IsBillable == true\n| summarize TodayGB = sum(Quantity) / 1024 by DataType\n| join kind=inner Baseline on DataType\n| extend ZScore = round((TodayGB - AvgGB) / StdGB, 2),\n         DeviationMB = round((TodayGB - AvgGB) * 1024, 1),\n         SpikeRatio = round(TodayGB / AvgGB, 1)\n| where ZScore > 3\n| project DataType, TodayGB = round(TodayGB, 3), AvgGB = round(AvgGB, 3), ZScore, DeviationMB, SpikeRatio",
        "read": "A huge Z-score on a table with tiny volume (a few MB) is noise from a new or quiet table; check its daily volume in step 5. Real spikes have a large <b>DeviationMB</b>."
      },
      {
        "ctx": "One table's volume today vs. its 14-day average",
        "kql": "let Avg14d = toscalar(\n    Usage\n    | where TimeGenerated between (ago(15d) .. ago(1d))\n    | where DataType == \"{{TABLE}}\"\n    | summarize DailyGB = sum(Quantity) / 1024 by bin(TimeGenerated, 1d)\n    | summarize avg(DailyGB));\nUsage\n| where TimeGenerated > ago(1d)\n| where DataType == \"{{TABLE}}\"\n| summarize TodayGB = round(sum(Quantity) / 1024, 3)\n| extend AvgDailyGB = round(Avg14d, 3),\n         SpikeRatio = round(TodayGB / Avg14d, 1),\n         ExcessMB = round((TodayGB - Avg14d) * 1024, 1)",
        "read": "Put the table name from the alert (e.g. ThreatIntelIndicators) in <b>Table name</b>. ExcessMB is what the spike actually cost."
      },
      {
        "ctx": "Threat-intel indicators by source (which feed pushed the extra indicators?)",
        "kql": "ThreatIntelIndicators\n| where TimeGenerated > ago(1d)\n| summarize Indicators = count() by SourceSystem\n| order by Indicators desc",
        "read": "A single feed or connector re-sending its whole indicator set explains most TI spikes; it usually settles the next day."
      },
      {
        "ctx": "Daily anomaly count by template (UEBA Anomalies table)",
        "kql": "Anomalies\n| where TimeGenerated > ago(15d)\n| summarize n = count() by Day = bin(TimeGenerated, 1d), AnomalyTemplateName\n| order by Day desc, n desc\n| take 30",
        "read": "If the Anomalies table itself spiked, the template with the jump tells you which behaviour to look at (for Office Exchange, see the UEBA Exchange anomaly entry)."
      },
      {
        "ctx": "Daily volume of one table (is it new or tiny?)",
        "kql": "Usage\n| where TimeGenerated > ago(14d)\n| where DataType == \"{{TABLE}}\"\n| summarize MB = round(sum(Quantity), 2) by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A table that only started a few days ago with a few MB per day inflates the Z-score; close as expected and let the baseline build."
      }
    ],
    "fp": "New connectors or tables (no baseline yet), threat-intel feed resyncs, and incident-driven verbose logging."
  },
  {
    "id": "sentinel-new-table",
    "name": "New table detected in Sentinel (App Insights / UEBA)",
    "cat": "SIEM health",
    "src": "Microsoft Sentinel (Usage, AzureActivity)",
    "sev": "low",
    "mitre": [],
    "playbook": true,
    "summary": "A table appeared in the workspace that wasn't there before. Find what produces it, who deployed or enabled it, and whether the content is expected.",
    "steps": [
      {
        "ctx": "Source of new Application Insights tables (app, resource, SDK, hosts)",
        "kql": "union withsource=Tbl AppDependencies, AppExceptions, AppTraces, AppRequests, AppMetrics, AppPerformanceCounters\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Records = count(), First = min(TimeGenerated), Last = max(TimeGenerated),\n            Apps = make_set(AppRoleName, 5), Res = make_set(_ResourceId, 3), SDK = make_set(SDKVersion, 3), Hosts = make_set(AppRoleInstance, 5) by Tbl\n| order by Records desc",
        "read": "The _ResourceId and AppRoleName name the product sending telemetry (for example a vendor's cloud connector)."
      },
      {
        "ctx": "Who deployed or modified the resource? (deployments and role assignments)",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where _ResourceId has \"{{RESOURCE}}\" or tostring(Properties) has \"{{RESOURCE}}\"\n| summarize n = count(), First = min(TimeGenerated) by Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue\n| order by First asc\n| take 25",
        "read": "Put part of the resource name from step 1 in <b>Azure resource</b>. A known admin from a corporate IP deploying a vendor connector is expected; confirm with the change ticket."
      },
      {
        "ctx": "Who enabled Sentinel settings, connectors or tables? (UEBA / behaviors)",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where OperationNameValue has_any (\"SECURITYINSIGHTS/SETTINGS\", \"SECURITYINSIGHTS/ONBOARDINGSTATES\", \"SECURITYINSIGHTS/DATACONNECTORS\", \"OPERATIONALINSIGHTS/WORKSPACES/TABLES\")\n| summarize n = count(), First = min(TimeGenerated) by Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue\n| order by First asc",
        "read": "Changes just before the SentinelBehavior* tables appeared explain them; match the Caller to the SOC or platform team."
      },
      {
        "ctx": "Content of the new behavior records",
        "kql": "SentinelBehaviorInfo\n| where TimeGenerated > ago(3d)\n| take 10",
        "read": "Standard UEBA output (entity, behavior type, scores) confirms the table is expected."
      },
      {
        "ctx": "Role assignments made by one caller",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Caller has \"{{ACTOR}}\" and OperationNameValue =~ \"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE\"\n| extend RoleDef = tostring(parse_json(tostring(Properties_d.requestbody)).Properties.RoleDefinitionId),\n         Principal = tostring(parse_json(tostring(Properties_d.requestbody)).Properties.PrincipalId)\n| project TimeGenerated, Caller, CallerIpAddress, _ResourceId, RoleDef, Principal, ActivityStatusValue",
        "read": "Put the caller (or part of the UPN) in <b>Actor</b>. Look up RoleDef to see which role was granted and to which Principal."
      }
    ],
    "fp": "Planned connector onboarding and UEBA enablement by the SOC or platform team."
  },
  {
    "id": "ca-policy-change",
    "name": "Defense evasion: Conditional Access policy created or updated by one user",
    "cat": "Identity",
    "src": "Entra ID (Sentinel AuditLogs / SigninLogs)",
    "sev": "medium",
    "mitre": [
      "T1556.009",
      "T1562"
    ],
    "playbook": true,
    "summary": "An account created or changed a Conditional Access policy. Confirm the sequence of changes, that the actor signed in normally (IP, location, MFA, device, risk), and who else changes CA policies.",
    "steps": [
      {
        "ctx": "Conditional Access and admin activity by the actor (14 days)",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where OperationName has \"conditional access\" or tostring(InitiatedBy) has \"{{ACTOR}}\"\n| extend Actor = tostring(InitiatedBy.user.userPrincipalName),\n         IP = tostring(InitiatedBy.user.ipAddress),\n         Target = tostring(TargetResources[0].displayName)\n| project TimeGenerated, OperationName, Actor, IP, Target, Result\n| order by TimeGenerated desc\n| take 40",
        "read": "Set the look-back to 14d. A <b>Report-only</b> policy created by an admin is low risk; disabling or excluding users from an enforced policy is not."
      },
      {
        "ctx": "Actor sign-in profile and 90-day CA change history",
        "kql": "union isfuzzy=true\n(SigninLogs\n | where TimeGenerated > ago({{LOOKBACK}})\n | where UserPrincipalName =~ \"{{ACTOR}}\"\n | summarize n = count(), fail = countif(ResultType != \"0\"),\n             First = min(TimeGenerated), Last = max(TimeGenerated),\n             Apps = make_set(AppDisplayName, 5), MFA = make_set(AuthenticationRequirement),\n             Dev = make_set(tostring(DeviceDetail.operatingSystem)), Risk = make_set(RiskLevelDuringSignIn)\n   by T = \"Signin\", IPAddress,\n      Loc = strcat(tostring(LocationDetails.countryOrRegion), \"/\", tostring(LocationDetails.city))),\n(AuditLogs\n | where TimeGenerated > ago(90d)\n | where OperationName has \"conditional access\"\n | summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated)\n   by T = \"CAhist\", IPAddress = tostring(InitiatedBy.user.userPrincipalName), Loc = OperationName)\n| order by T, n desc",
        "read": "Signin rows should show the actor's usual IPs and countries with MFA and no risk. CAhist rows show who normally changes CA policies (the IPAddress column holds the admin UPN there)."
      },
      {
        "ctx": "Failure codes for the actor's failed sign-ins",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{ACTOR}}\"\n| summarize n = count() by ResultType, ResultDescription\n| order by n desc",
        "read": "50074/50076 are routine MFA prompts. 50126 (bad password) bursts or 53003 (blocked by CA) from new IPs need a closer look."
      }
    ],
    "fp": "Admins piloting policies in Report-only mode, and vendor or partner admin accounts doing planned CA work."
  },
  {
    "id": "ueba-exchange-anomaly",
    "name": "UEBA: anomalous Office Exchange activity / inbox rule changes",
    "cat": "Email",
    "src": "Sentinel UEBA (Anomalies) + Exchange Online (OfficeActivity)",
    "sev": "medium",
    "mitre": [
      "T1564.008",
      "T1114.003"
    ],
    "playbook": true,
    "summary": "UEBA flagged anomalous Exchange activity, often UpdateInboxRules. Check the anomaly details, whether mailbox access spiked tenant-wide, and what the user's rules actually do.",
    "steps": [
      {
        "ctx": "Exchange anomaly details (users, scores, reasons)",
        "kql": "Anomalies\n| where TimeGenerated > ago({{LOOKBACK}})\n| where AnomalyTemplateName == \"Anomalous user activities in Office Exchange\"\n| extend Reasons = tostring(AnomalyReasons)\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated), MaxScore = max(Score),\n            Users = dcount(UserName), SampleUsers = make_set(UserName, 8),\n            SampleDesc = take_any(Description), SampleReason = take_any(substring(Reasons, 0, 400))",
        "read": "One or two users with low scores and reasons like 'first time UpdateInboxRules' is usually a user tidying their mailbox. Many users at once points to a tenant-wide change."
      },
      {
        "ctx": "Tenant-wide MailItemsAccessed trend (real mass mailbox access?)",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Operation == \"MailItemsAccessed\"\n| summarize Events = count(), Users = dcount(UserId), IPs = dcount(ClientIP) by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A flat daily trend means there was no mass mailbox access."
      },
      {
        "ctx": "Inbox rule changes by the user (with source IP)",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserId has \"{{UPN}}\"\n| where Operation in~ (\"New-InboxRule\", \"Set-InboxRule\", \"UpdateInboxRules\", \"Remove-InboxRule\", \"Set-Mailbox\")\n| project TimeGenerated, Operation, UserId, ClientIP, Parameters, OperationProperties\n| order by TimeGenerated asc",
        "read": "Put the user (or part of the UPN) in <b>User (UPN)</b>. Compare ClientIP with the user's sign-in IPs in step 5."
      },
      {
        "ctx": "Inbox rule actions (forward / redirect / delete / move)",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserId has \"{{UPN}}\" and Operation =~ \"UpdateInboxRules\"\n| mv-expand prop = parse_json(OperationProperties)\n| extend Name = tostring(prop.Name), Value = tostring(prop.Value)\n| where Name in~ (\"RuleName\", \"RuleActions\", \"RuleCondition\", \"RuleOperation\", \"RuleState\")\n| summarize Values = make_set(Value, 20) by Name",
        "read": "<b>Forward</b>, <b>Redirect</b>, <b>Delete</b> or moving to RSS / Archive / a hidden folder, especially with conditions on words like invoice or payment, is an attacker rule. Sorting newsletters into a folder is normal."
      },
      {
        "ctx": "User's interactive sign-in profile (location, MFA, risk)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName has \"{{UPN}}\"\n| summarize n = count(), fail = countif(ResultType != \"0\"), First = min(TimeGenerated), Last = max(TimeGenerated),\n            Apps = make_set(AppDisplayName, 5), MFA = make_set(AuthenticationRequirement), Risk = make_set(RiskLevelDuringSignIn)\n  by IPAddress, Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city)\n| order by n desc",
        "read": "Familiar IPs and countries with MFA and no risk support a benign verdict."
      },
      {
        "ctx": "Non-interactive sign-ins (which session made the rule change?)",
        "kql": "AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName has \"{{UPN}}\"\n| summarize n = count(), fail = countif(ResultType != \"0\"), Apps = make_set(AppDisplayName, 5)\n  by IPAddress, Country = tostring(parse_json(LocationDetails).countryOrRegion), City = tostring(parse_json(LocationDetails).city)\n| order by n desc",
        "read": "Rule changes often come from Outlook or mobile mail refreshing a token, with no interactive sign-in. The rule-change ClientIP should appear here from a known location."
      }
    ],
    "fp": "Users creating sorting rules, Outlook clients syncing rules, and new UEBA baselines after a tenant change."
  },
  {
    "id": "waf-malicious-request",
    "name": "Malicious web request executed against a web server (App Gateway WAF)",
    "cat": "Network",
    "src": "Azure Application Gateway WAF (Sentinel)",
    "sev": "medium",
    "mitre": [
      "T1190",
      "T1595.002"
    ],
    "playbook": true,
    "summary": "The WAF flagged web requests that may have reached the server. Find the WAF table, check detection vs. prevention mode, and whether any flagged client got a successful response on a sensitive path.",
    "steps": [
      {
        "ctx": "Locate the WAF log table (AzureDiagnostics vs. AGWAccessLogs / AGWFirewallLogs)",
        "kql": "union isfuzzy=true\n(AzureDiagnostics | where TimeGenerated > ago(3d) | where Category has_any (\"ApplicationGateway\", \"FrontDoor\", \"WebApplicationFirewall\") | summarize n = count() by Src = strcat(\"AzureDiagnostics: \", Category)),\n(AGWAccessLogs | where TimeGenerated > ago(3d) | summarize n = count() by Src = \"AGWAccessLogs\"),\n(AGWFirewallLogs | where TimeGenerated > ago(3d) | summarize n = count() by Src = \"AGWFirewallLogs\"),\n(AzureDiagnostics | where TimeGenerated > ago(3d) | where ResourceType has_any (\"APPLICATIONGATEWAYS\", \"FRONTDOORS\", \"PROFILES\") | summarize n = count() by Src = strcat(\"ResourceType: \", ResourceType))\n| order by n desc",
        "read": "The next steps use AGWAccessLogs / AGWFirewallLogs (resource-specific tables). If only AzureDiagnostics has data, adapt the column names."
      },
      {
        "ctx": "WAF mode check: actions per hostname (Blocked / Detected / Matched)",
        "kql": "AGWFirewallLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Hostname has \"{{DOMAIN}}\"\n| summarize Events = count(), IPs = dcount(ClientIp) by Hostname, Action, PolicyMode = tostring(column_ifexists(\"PolicyMode\", \"\"))\n| order by Events desc",
        "read": "Put the site names (or a fragment, e.g. the brand name) in <b>Domain / URL fragment</b>. Only <b>Detected / Matched</b> and no Blocked means the WAF is in detection mode and attacks reach the backend."
      },
      {
        "ctx": "What did WAF-flagged clients reach with a success status?",
        "kql": "let FlaggedIPs = AGWFirewallLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Hostname has \"{{DOMAIN}}\"\n| where Action in~ (\"Blocked\", \"Detected\", \"Matched\")\n| distinct ClientIp;\nAGWAccessLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Host has \"{{DOMAIN}}\"\n| where ClientIp in (FlaggedIPs)\n| where tostring(HttpStatus) in (\"200\", \"101\", \"201\", \"202\", \"204\", \"301\", \"302\")\n| summarize Requests = count(), Methods = make_set(HttpMethod), URIs = make_set(RequestUri, 25), Statuses = make_set(HttpStatus)\n  by ClientIp, Host\n| order by Requests desc",
        "read": "Flagged bots that only got the home page or static files are noise. Successful hits on login, upload or API paths need step 5."
      },
      {
        "ctx": "WAF rule hits by client (bot classification vs. exploit signatures)",
        "kql": "AGWFirewallLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Hostname has \"{{DOMAIN}}\"\n| summarize Hits = count(), Actions = make_set(Action), Rules = make_set(strcat(RuleId, \" - \", Message), 10), URIs = make_set(RequestUri, 10)\n  by ClientIp, Hostname\n| order by Hits desc\n| take 50",
        "read": "Bot / scanner rules (user-agent, missing headers) are low risk; SQLi, RCE, LFI or path-traversal rules on the same client are an exploit attempt."
      },
      {
        "ctx": "Successful hits on high-risk paths (.env, .git, admin, traversal, injection)",
        "kql": "AGWAccessLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where HttpStatus between (200 .. 299)\n| where RequestUri has_any (\".env\", \"wp-admin\", \"wp-login\", \"xmlrpc\", \"phpmyadmin\", \"/cgi-bin\", \"../\", \"%2e%2e\", \"/etc/passwd\", \"cmd=\", \"exec\", \"union select\", \"/.git\", \"/actuator\", \"/admin\", \"shell\")\n| project TimeGenerated, ClientIp, Host, HttpMethod, RequestUri, HttpStatus, UserAgent\n| order by TimeGenerated asc",
        "read": "Any 2xx on <b>.env</b>, <b>.git</b>, <b>/etc/passwd</b> or an injection string means the attack may have worked: check the response size and escalate."
      },
      {
        "ctx": "WAF verdict joined to the backend response (what did the server return?)",
        "kql": "AGWFirewallLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Hostname has \"{{DOMAIN}}\"\n| where Action in~ (\"Detected\", \"Matched\")\n| project TransactionId, ClientIp, Hostname, RuleId, Message, Action, FwUri = RequestUri\n| join kind=inner (\n    AGWAccessLogs\n    | where TimeGenerated > ago({{LOOKBACK}})\n    | project TransactionId, HttpMethod, RequestUri, HttpStatus, UserAgent\n  ) on TransactionId\n| where tostring(HttpStatus) startswith \"2\"\n| summarize Hits = count(), Rules = make_set(strcat(RuleId, \" - \", Message), 5), URIs = make_set(RequestUri, 10), Statuses = make_set(HttpStatus) by ClientIp, Hostname\n| order by Hits desc",
        "read": "Each row is a request the WAF only detected and the backend answered with 2xx. These are the ones to review with the application owner."
      },
      {
        "ctx": "Alert record and stored rule logic",
        "kql": "SecurityAlert\n| where TimeGenerated > ago({{LOOKBACK}})\n| where AlertName == \"{{ALERTNAME}}\"\n| project TimeGenerated, AlertName, Description, ExtendedProperties, Entities\n| take 5",
        "read": "Put the alert title in <b>Alert name</b>. ExtendedProperties shows the data source, thresholds and mode without opening the analytics rule."
      },
      {
        "ctx": "Every request from the IP with the WAF verdict (what did the blocked requests try?)",
        "kql": "let FW = AGWFirewallLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ClientIp == \"{{IP}}\"\n| summarize Actions = make_set(Action), Rules = make_set(strcat(RuleId, \" - \", Message), 5) by TransactionId, FwUri = RequestUri, Hostname;\nAGWAccessLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ClientIp == \"{{IP}}\"\n| join kind=leftouter FW on TransactionId\n| project TimeGenerated, Host, HttpMethod, RequestUri, HttpStatus, Actions, Rules, UserAgent\n| order by TimeGenerated asc",
        "read": "Put the client IP from the alert in <b>IP address</b>. Each row is one request with the WAF action and rule beside the server response; rows with <b>Blocked</b> show what the attacker tried, and empty Actions means the WAF didn't flag that request."
      },
      {
        "ctx": "Other activity from the IP across all sites (look-back window)",
        "kql": "AGWAccessLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ClientIp == \"{{IP}}\"\n| summarize Requests = count(), Statuses = make_set(HttpStatus), URIs = make_set(RequestUri, 15), First = min(TimeGenerated), Last = max(TimeGenerated) by Host, HttpMethod\n| order by Requests desc",
        "read": "Several hostnames from one IP means it is scanning the client's sites, not targeting one app. Mostly 403/404 statuses is a failed scan."
      },
      {
        "ctx": "Successful responses on high-risk paths from the IP",
        "kql": "AGWAccessLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ClientIp == \"{{IP}}\"\n| where HttpStatus between (200 .. 299)\n| where RequestUri has_any (\".env\", \"wp-admin\", \"wp-login\", \"xmlrpc\", \"phpmyadmin\", \"/cgi-bin\", \"../\", \"%2e%2e\", \"/etc/passwd\", \"cmd=\", \"exec\", \"union select\", \"/.git\", \"/actuator\", \"/admin\", \"shell\")\n| project TimeGenerated, Host, HttpMethod, RequestUri, HttpStatus, UserAgent",
        "read": "No rows confirms none of the exploit or sensitive paths (admin, login, .env, .git, traversal, injection) returned success. Any row needs the response checked with the application owner."
      }
    ],
    "fp": "Internet scanners and search-engine bots hit every site; with the WAF in detection mode they show as Detected but get only 404s or static pages."
  },
  {
    "id": "waf-react2shell",
    "name": "App Gateway WAF – code injection (React2Shell, CVE-2025-55182)",
    "cat": "Network",
    "src": "Azure Application Gateway WAF + Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1190",
      "T1059"
    ],
    "playbook": true,
    "summary": "The WAF matched React2Shell exploit payloads from an external IP. Check which hosts were hit and what they returned, whether the WAF blocked them, whether the target runs Next.js, and any post-exploit activity on the backend.",
    "steps": [
      {
        "ctx": "Requests from the attacker that reached the App Gateway",
        "kql": "AGWAccessLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ClientIp == \"{{IP}}\"\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated), Bytes = sum(SentBytes), Backend = make_set(tostring(column_ifexists(\"ServerRouted\", \"\")), 3)\n  by OriginalHost = tostring(column_ifexists(\"OriginalHost\", Host)), Status = tostring(HttpStatus), HttpMethod, RequestUri\n| order by First asc",
        "read": "Note the backend (ServerRouted) for any 2xx response to the exploit request; that server is the one to check in step 4."
      },
      {
        "ctx": "WAF verdicts per hour (Detected vs. Blocked) and matched rules",
        "kql": "AGWFirewallLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ClientIp == \"{{IP}}\"\n| summarize n = count(), Tx = dcount(TransactionId), Rules = make_set(strcat(RuleId, \" \", Message), 8) by Hour = bin(TimeGenerated, 1h), Hostname, Action\n| order by Hour asc",
        "read": "<b>Blocked</b> means the payload never reached the app. <b>Detected</b> only means it did."
      },
      {
        "ctx": "Web technology fingerprint per site (Next.js is exposed; WordPress/PHP is not)",
        "kql": "AGWAccessLogs\n| where TimeGenerated > ago(3d)\n| extend OH = tostring(column_ifexists(\"OriginalHost\", Host))\n| where OH has \"{{DOMAIN}}\"\n| summarize Total = count(), NextJS = countif(RequestUri has \"/_next/\"), WordPress = countif(RequestUri has_any (\"/wp-content/\", \"/wp-includes/\", \"/wp-json\")), PHP = countif(RequestUri has \".php\"), Backend = make_set(tostring(column_ifexists(\"ServerRouted\", \"\")), 3) by OH\n| order by Total desc",
        "read": "Put the targeted site names (or fragments) in <b>Domain / URL fragment</b>. Only sites with <b>/_next/</b> traffic run Next.js and are exposed to CVE-2025-55182."
      },
      {
        "ctx": "Post-exploit activity on the backend (processes, outbound, new files, alerts)",
        "kql": "union isfuzzy=true\n(DeviceProcessEvents | where Timestamp > ago({{LOOKBACK}}) | where DeviceName has \"{{DEVICE}}\"\n | summarize n = count() by Src = \"Proc\", Parent = InitiatingProcessFileName, Detail = strcat(FileName, \" :: \", substring(ProcessCommandLine, 0, 140))),\n(DeviceNetworkEvents | where Timestamp > ago({{LOOKBACK}}) | where DeviceName has \"{{DEVICE}}\" | where RemoteIPType == \"Public\" and ActionType in (\"ConnectionSuccess\", \"ConnectionAttempt\")\n | summarize n = count() by Src = \"NetOut\", Parent = InitiatingProcessFileName, Detail = strcat(RemoteIP, \":\", RemotePort, \" \", RemoteUrl)),\n(DeviceFileEvents | where Timestamp > ago({{LOOKBACK}}) | where DeviceName has \"{{DEVICE}}\" | where ActionType == \"FileCreated\"\n | summarize n = count() by Src = \"FileNew\", Parent = InitiatingProcessFileName, Detail = FolderPath),\n(AlertInfo | where Timestamp > ago({{LOOKBACK}}) | join kind=inner (AlertEvidence | where DeviceName has \"{{DEVICE}}\") on AlertId | summarize n = count() by Src = \"Alerts\", Parent = ServiceSource, Detail = Title)\n| order by Src, n desc",
        "read": "Put the backend VM in <b>Device name</b> and set the look-back to the hour after the attack. <b>node</b> spawning sh/bash/curl/wget, new outbound connections from node, or new files in /tmp mean exploitation."
      },
      {
        "ctx": "Hunt for React2Shell attempts across all hosts (30 days)",
        "kql": "AGWFirewallLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where RuleId == \"99001018\"    // CVE-2025-55182 (React2Shell) rule\n| summarize count() by ClientIp, Hostname, Action",
        "read": "Shows other attackers and other sites hit by the same rule. Check the rule ID matches your WAF policy."
      }
    ],
    "fp": "Vulnerability scanners sending the public PoC to every site; harmless against non-Next.js backends or when the WAF blocks."
  },
  {
    "id": "remote-access-certutil",
    "name": "Uncommon remote access software + certutil decode on one endpoint",
    "cat": "Endpoint",
    "src": "Defender for Endpoint",
    "sev": "medium",
    "mitre": [
      "T1219",
      "T1140",
      "T1021.004"
    ],
    "playbook": true,
    "summary": "Remote access software (e.g. Tailscale) and certutil -decode on the same laptop. Separate an approved automation or PoC from an attacker's persistence and tool staging.",
    "steps": [
      {
        "ctx": "Alert evidence for the endpoint (entities, files, command lines)",
        "kql": "AlertEvidence\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName has \"{{DEVICE}}\"\n| summarize n = count() by Title, EntityType, EvidenceRole, FileName, ProcessCommandLine = substring(ProcessCommandLine, 0, 200), SHA256\n| order by Title",
        "read": "Lists what each alert recorded; note the accounts and hashes for the next steps."
      },
      {
        "ctx": "certutil and remote-access process activity (decode vs. download)",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName has \"{{DEVICE}}\"\n| where FileName in~ (\"certutil.exe\", \"tailscale.exe\", \"tailscaled.exe\", \"tailscale-ipn.exe\") or ProcessCommandLine has_any (\"certutil\", \"tailscale\") or InitiatingProcessFileName has \"tailscale\"\n| summarize n = count(), First = min(Timestamp), Last = max(Timestamp) by FileName, Cmd = substring(ProcessCommandLine, 0, 220), Parent = InitiatingProcessFileName, Account = AccountName\n| order by First asc",
        "read": "<b>certutil -decode</b> of a local file by a script tool is common in automation; <b>certutil -urlcache -f http…</b> is a download and is suspicious."
      },
      {
        "ctx": "Decode the base64 content passed to certutil",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName has \"{{DEVICE}}\"\n| where FileName =~ \"certutil.exe\"\n| extend B64 = extract(@\"echo ([A-Za-z0-9+/=]{20,})\", 1, InitiatingProcessCommandLine)\n| extend Decoded = base64_decode_tostring(B64)\n| project Timestamp, AccountName, ProcessCommandLine, Decoded",
        "read": "Read <b>Decoded</b>: generated .cmd helper scripts from an automation tool are benign; anything that downloads, adds users or opens a shell is not."
      },
      {
        "ctx": "SSH source, logons of the automation account, and remote-access install",
        "kql": "union isfuzzy=true\n(DeviceLogonEvents | where Timestamp > ago({{LOOKBACK}}) | where DeviceName has \"{{DEVICE}}\" | where AccountName =~ \"{{ACCOUNT}}\"\n | summarize n = count(), First = min(Timestamp), Last = max(Timestamp) by Src = \"Account logon\", Detail = strcat(ActionType, \" \", LogonType, \" \", RemoteIP)),\n(DeviceNetworkEvents | where Timestamp > ago({{LOOKBACK}}) | where DeviceName has \"{{DEVICE}}\" | where ActionType == \"InboundConnectionAccepted\" and LocalPort == 22\n | summarize n = count(), First = min(Timestamp), Last = max(Timestamp) by Src = \"SSH Inbound (port 22)\", Detail = RemoteIP),\n(DeviceFileEvents | where Timestamp > ago({{BASELINE}}) | where DeviceName has \"{{DEVICE}}\" | where FileName in~ (\"tailscaled.exe\", \"tailscale-ipn.exe\") or FileName startswith \"tailscale-setup\"\n | summarize n = count(), First = min(Timestamp), Last = max(Timestamp) by Src = \"Tailscale install\", Detail = strcat(ActionType, \" \", FileName))\n| order by Src, First asc",
        "read": "Put the automation / local account (e.g. n8n) in <b>Account name</b>. Inbound SSH from a Tailscale (100.64.0.0/10) address is the user's own tunnel; from an internet IP it is exposure."
      },
      {
        "ctx": "Everything the account executed",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName has \"{{DEVICE}}\"\n| where AccountName =~ \"{{ACCOUNT}}\"\n| summarize n = count(), First = min(Timestamp), Last = max(Timestamp) by Parent = InitiatingProcessFileName, FileName\n| order by n desc",
        "read": "Expect the automation runtime (node, cmd, certutil). Recon (whoami, net, nltest), credential tools or new remote-access binaries are not part of a PoC."
      }
    ],
    "fp": "Approved PoCs and personal VPN/mesh tools on developer laptops; automation platforms (n8n, Power Automate Desktop) that use certutil to decode their own scripts."
  },
  {
    "id": "service-account-compromise",
    "name": "Execution & credential access on a service account (weak password / attack analysis)",
    "cat": "Identity",
    "src": "Entra ID / Defender for Identity / Defender for Cloud Apps",
    "sev": "high",
    "mitre": [
      "T1078",
      "T1110"
    ],
    "playbook": true,
    "summary": "A service or RPA account was flagged for a weak password and possible compromise from a cloud IP. Check whether the IP is the account's normal source, whether it sprays other accounts, and what the account did.",
    "steps": [
      {
        "ctx": "Sign-in history for the account (14 days, interactive + non-interactive)",
        "kql": "let I = SigninLogs | where TimeGenerated > ago({{LOOKBACK}}) | where UserPrincipalName =~ \"{{UPN}}\" or UserId == \"{{OBJECTID}}\" | extend Loc = todynamic(LocationDetails), T = \"Interactive\";\nlet N = AADNonInteractiveUserSignInLogs | where TimeGenerated > ago({{LOOKBACK}}) | where UserPrincipalName =~ \"{{UPN}}\" or UserId == \"{{OBJECTID}}\" | extend Loc = todynamic(LocationDetails), T = \"NonInteractive\";\nunion I, N\n| summarize n = count(), fail = countif(ResultType != \"0\"), First = min(TimeGenerated), Last = max(TimeGenerated),\n            Apps = make_set(AppDisplayName, 10), MFA = make_set(AuthenticationRequirement), Errors = make_set(ResultType, 10)\n  by IPAddress, Country = tostring(Loc.countryOrRegion), City = tostring(Loc.city), T\n| order by Last desc",
        "read": "Set the look-back to 14d. If the flagged IP has signed in every day for weeks from the same cloud region, it is the bot's home; new IPs, interactive sign-ins or failures are the warning signs."
      },
      {
        "ctx": "All accounts seen from the IP (spray check)",
        "kql": "let I = SigninLogs | where TimeGenerated > ago({{LOOKBACK}}) | where IPAddress == \"{{IP}}\" | extend T = \"Interactive\";\nlet N = AADNonInteractiveUserSignInLogs | where TimeGenerated > ago({{LOOKBACK}}) | where IPAddress == \"{{IP}}\" | extend T = \"NonInteractive\";\nunion I, N\n| summarize n = count(), Success = countif(ResultType == \"0\"), Fail = countif(ResultType != \"0\"),\n            Users = dcount(UserPrincipalName), UserList = make_set(UserPrincipalName, 25) by T",
        "read": "One account from the IP is a dedicated server; many accounts with failures is password spraying from attacker infrastructure."
      },
      {
        "ctx": "Alert evidence and reasons for the account",
        "kql": "AlertEvidence\n| where Timestamp > ago({{LOOKBACK}})\n| where AccountUpn =~ \"{{UPN}}\" or AccountObjectId == \"{{OBJECTID}}\"\n| project Timestamp, Title, ServiceSource, EntityType, EvidenceRole, AccountUpn, AccountName, RemoteIP, Application, AdditionalFields\n| order by Timestamp asc",
        "read": "Shows which detection source flagged what (weak password, attack analysis, insider risk)."
      },
      {
        "ctx": "Account activity after sign-in (Entra audit, M365, Defender for Cloud Apps)",
        "kql": "union\n(AuditLogs | where TimeGenerated > ago(3d)\n   | where tostring(InitiatedBy) has_any (\"{{UPN}}\", \"{{OBJECTID}}\") or tostring(TargetResources) has_any (\"{{UPN}}\", \"{{OBJECTID}}\")\n   | project TimeGenerated, Src = \"Audit\", Action = OperationName, IP = tostring(InitiatedBy.user.ipAddress)),\n(OfficeActivity | where TimeGenerated > ago(3d)\n   | where UserId =~ \"{{UPN}}\"\n   | project TimeGenerated, Src = \"M365\", Action = Operation, IP = ClientIP),\n(CloudAppEvents | where Timestamp > ago(3d)\n   | where AccountObjectId == \"{{OBJECTID}}\" or AccountId == \"{{OBJECTID}}\"\n   | project TimeGenerated = Timestamp, Src = \"MDA\", Action = ActionType, IP = IPAddress)\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated), IPs = make_set(IP, 10) by Src, Action\n| order by n desc",
        "read": "Expect the bot's usual actions (MailItemsAccessed, file sync). Inbox rules, forwarding, new app consents or directory changes mean the account was misused."
      },
      {
        "ctx": "Identity logon events (Defender for Identity) per source IP",
        "kql": "IdentityLogonEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where AccountUpn =~ \"{{UPN}}\" or AccountObjectId == \"{{OBJECTID}}\"\n| summarize n = count(), Success = countif(ActionType == \"LogonSuccess\"), Fail = countif(ActionType == \"LogonFailed\"),\n            First = min(Timestamp), Last = max(Timestamp), Protocols = make_set(Protocol), FailReasons = make_set(FailureReason, 5)\n  by DeviceName, IPAddress, DestinationDeviceName, LogonType\n| order by Last desc",
        "read": "Reconstructs the Login / KMSI / OAuth2 sequence. Failures before a success from a new IP are the compromise pattern."
      }
    ],
    "fp": "RPA and integration accounts that legitimately run from a cloud provider IP every day; weak-password flags on accounts that can't use MFA (fix with a strong secret and CA, not escalation)."
  },
  {
    "id": "noninteractive-vpn-signin",
    "name": "Non-interactive sign-in from a VPN / hosting IP",
    "cat": "Identity",
    "src": "Entra ID (Sentinel SigninLogs / AADNonInteractiveUserSignInLogs)",
    "sev": "medium",
    "mitre": [
      "T1078.004",
      "T1550.001"
    ],
    "playbook": true,
    "summary": "A token refresh (e.g. iOS Mail / Apple Internet Accounts) came from a VPN or hosting IP. Check whether the network is normal for the user, whether the session is being replayed elsewhere, and what the session did. For inbox rules and Entra changes, also run the 'mailbox and account audit' entry.",
    "steps": [
      {
        "ctx": "Sign-in baseline for the user (14 days, IP / ASN / location)",
        "kql": "let Interactive = SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| extend Loc = todynamic(LocationDetails), Dev = todynamic(DeviceDetail), SignInType = \"Interactive\";\nlet NonInteractive = AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| extend Loc = todynamic(LocationDetails), Dev = todynamic(DeviceDetail), SignInType = \"NonInteractive\";\nunion Interactive, NonInteractive\n| extend Country = tostring(Loc.countryOrRegion), City = tostring(Loc.city), OS = tostring(Dev.operatingSystem)\n| summarize n = count(), fail = countif(ResultType != \"0\"), First = min(TimeGenerated), Last = max(TimeGenerated),\n            Apps = make_set(AppDisplayName, 5), OSs = make_set(OS)\n  by IPAddress, AutonomousSystemNumber, Country, City, SignInType\n| order by Last desc",
        "read": "Set the look-back to 14d. A VPN/hosting ASN the user has used for weeks is their VPN; a first appearance in a new country is the warning sign."
      },
      {
        "ctx": "Same session used from other IPs (token replay check)",
        "kql": "let Interactive = SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where SessionId == \"{{SESSIONID}}\"\n| extend Loc = todynamic(LocationDetails), SignInType = \"Interactive\";\nlet NonInteractive = AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where SessionId == \"{{SESSIONID}}\"\n| extend Loc = todynamic(LocationDetails), SignInType = \"NonInteractive\";\nunion Interactive, NonInteractive\n| extend Country = tostring(Loc.countryOrRegion), City = tostring(Loc.city)\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated), Apps = make_set(AppDisplayName, 5)\n  by IPAddress, Country, City, UserAgent, SignInType\n| order by First asc",
        "read": "Put the SessionId from the sign-in in <b>Session ID</b>. The same session from distant IPs at overlapping times, especially with different user agents, is token theft."
      },
      {
        "ctx": "Other accounts from the IP (campaign infrastructure vs. one user's VPN)",
        "kql": "union SigninLogs, AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where IPAddress == \"{{IP}}\"\n| summarize n = count(), Users = make_set(UserPrincipalName, 20), Apps = make_set(AppDisplayName, 10), Results = make_set(ResultType)",
        "read": "Only this user means a personal VPN exit; several unrelated users means shared attacker infrastructure."
      },
      {
        "ctx": "Mailbox activity by operation and client IP",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserId =~ \"{{UPN}}\"\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Operation, ClientIP\n| order by n desc",
        "read": "A mail client refreshing shows MailItemsAccessed / Sync from the same IP. Send, inbox-rule or forwarding operations from the VPN IP need the mailbox audit entry."
      },
      {
        "ctx": "VPN / hosting / Tor classification of every sign-in network (30 days, reusable)",
        "kql": "let VpnHostingASN = dynamic([62240, 9009, 60068, 212238, 136787, 207137, 203020, 14061, 16276, 24940, 20473, 63949, 51167, 60781, 28753, 16265, 40676, 8100, 174, 9002]);\nlet PrivacyRelayASN = dynamic([36183, 13335]);\nlet Interactive = SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| extend Loc = todynamic(LocationDetails), Dev = todynamic(DeviceDetail), Risk = tostring(RiskEventTypes_V2), NetLoc = tostring(NetworkLocationDetails), SignInType = \"Interactive\";\nlet NonInteractive = AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| extend Loc = todynamic(LocationDetails), Dev = todynamic(DeviceDetail), Risk = tostring(RiskEventTypes_V2), NetLoc = tostring(NetworkLocationDetails), SignInType = \"NonInteractive\";\nunion Interactive, NonInteractive\n| extend ASN = toint(AutonomousSystemNumber), Country = tostring(Loc.countryOrRegion), City = tostring(Loc.city),\n         OS = tostring(Dev.operatingSystem), Managed = tostring(Dev.isManaged)\n| extend NetworkType = case(\n         Risk has_any (\"anonymizedIPAddress\", \"tor\"), \"Anonymous/Tor (Entra)\",\n         ASN in (VpnHostingASN), \"VPN/Hosting\",\n         ASN in (PrivacyRelayASN), \"Privacy Relay\",\n         NetLoc has \"trustedNamedLocation\", \"Trusted Named Location\",\n         \"ISP/Other\")\n| summarize SignIns = count(), Failed = countif(ResultType != \"0\"), First = min(TimeGenerated), Last = max(TimeGenerated),\n            Apps = make_set(AppDisplayName, 5), OSs = make_set(OS), Managed = make_set(Managed), Types = make_set(SignInType), Sessions = dcount(SessionId)\n  by NetworkType, IPAddress, ASN, Country, City\n| extend Flag = iff(NetworkType in (\"VPN/Hosting\", \"Anonymous/Tor (Entra)\"), \"Review\", \"\")\n| order by Flag desc, Last desc",
        "read": "Rows flagged <b>Review</b> are VPN/hosting or Tor networks. iCloud Private Relay (Privacy Relay) is common on iPhones and lower risk. Extend VpnHostingASN with ASNs you see in your tenant."
      }
    ],
    "fp": "Personal or corporate VPNs, iCloud Private Relay, and mobile mail apps refreshing tokens while travelling."
  },
  {
    "id": "ngfw-malicious-ip-auth",
    "name": "NGFW: successful authentication from a malicious IP (GlobalProtect / RADIUS)",
    "cat": "Network",
    "src": "CrowdStrike Falcon Next-Gen SIEM (LogScale CQL) – Palo Alto NGFW",
    "sev": "high",
    "mitre": [
      "T1133",
      "T1078"
    ],
    "playbook": true,
    "summary": "A VPN / RADIUS login succeeded from an IP on a threat-intel list. These are LogScale CQL queries for CrowdStrike Falcon Next-Gen SIEM, not KQL. Check whether the IP is normal for the user, brute force before the success, and what the session accessed.",
    "steps": [
      {
        "ctx": "Login history for the user (is the flagged IP a usual source?)",
        "kql": "#event.module=ngfw user.name=\"{{ACCOUNT}}\"\n| event.action=/auth-success|auth-fail/\n| groupBy([source.ip, event.action], function=[count(), min(@timestamp, as=First), max(@timestamp, as=Last)])\n| sort(First, order=asc)",
        "read": "LogScale CQL: run in Falcon Next-Gen SIEM search and set the time range there (e.g. 30 days). Put one username in <b>Account name</b>. A residential IP the user has used for weeks is their home connection."
      },
      {
        "ctx": "All activity from the flagged IP (accounts, VPN lifecycle)",
        "kql": "source.ip=\"{{IP}}\"\n| groupBy([user.name, event.action, #event.dataset], function=[count(), min(@timestamp, as=First), max(@timestamp, as=Last)])",
        "read": "One user from the IP supports a home/ISP connection; many users is attacker infrastructure."
      },
      {
        "ctx": "Failed logins for the user (brute force / credential stuffing first?)",
        "kql": "#event.module=ngfw user.name=\"{{ACCOUNT}}\" event.action=\"auth-fail\"\n| table([@timestamp, source.ip, vendor.description])",
        "read": "Many failures from varied IPs just before the success is credential stuffing."
      },
      {
        "ctx": "GlobalProtect session timeline",
        "kql": "#event.module=ngfw #event.dataset=/globalprotect/i user.name=\"{{ACCOUNT}}\"\n| table([@timestamp, source.ip, vendor.event, vendor.description])\n| sort(@timestamp, order=desc)",
        "read": "Note the IP assigned to the VPN session for the next step."
      },
      {
        "ctx": "Traffic from the VPN-assigned IP after login",
        "kql": "#event.module=ngfw #event.dataset=ngfw.traffic source.ip=\"{{INTIP}}\"\n| groupBy([destination.ip, destination.port, network.application], function=count())\n| sort(_count, order=desc)\n| head(50)",
        "read": "Put the GlobalProtect-assigned IP in <b>Internal IP</b>. Normal user apps are expected; SMB/RDP to many servers or admin consoles from a flagged login is not."
      },
      {
        "ctx": "IoC-matched successful logins across all users (spray check)",
        "kql": "#event.module=ngfw event.action=\"auth-success\" ioc.detected=true\n| groupBy([user.name, source.ip], function=count())",
        "read": "More than one user authenticating from flagged IPs widens the incident."
      }
    ],
    "fp": "Residential ISP IPs that rotated into a threat feed after use by another customer; the user's normal home connection."
  },
  {
    "id": "cross-signal-ip",
    "name": "Cross-signal IP match: firewall + Entra sign-in",
    "cat": "Network",
    "src": "Sentinel (SecurityAlert, SigninLogs, CommonSecurityLog)",
    "sev": "medium",
    "mitre": [
      "T1078",
      "T1071"
    ],
    "playbook": true,
    "summary": "The same IP appeared in firewall logs and Entra sign-ins. Often a corporate office egress or site-to-site VPN IP; prove it with the alert history, sign-in profile and firewall traffic before requesting an allowlist.",
    "steps": [
      {
        "ctx": "Past alerts for the IP (60 days)",
        "kql": "SecurityAlert\n| where TimeGenerated > ago(60d)\n| where Entities has \"{{IP}}\" or AlertName has \"{{IP}}\"\n| summarize Alerts = count(), First = min(TimeGenerated), Last = max(TimeGenerated), Days = dcount(bin(TimeGenerated, 1d)) by AlertName\n| order by Alerts desc\n| take 5",
        "read": "The same rule firing on the same IP most days is a tuning problem; use the counts in the allowlist request."
      },
      {
        "ctx": "Entra sign-in profile from the IP (users, success, country, risk, compliance, named location)",
        "kql": "let I = SigninLogs | where TimeGenerated > ago({{BASELINE}}) | where IPAddress == \"{{IP}}\" | extend Loc = todynamic(LocationDetails), Dev = todynamic(DeviceDetail), T = \"Interactive\";\nlet N = AADNonInteractiveUserSignInLogs | where TimeGenerated > ago({{BASELINE}}) | where IPAddress == \"{{IP}}\" | extend Loc = todynamic(LocationDetails), Dev = todynamic(DeviceDetail), T = \"NonInteractive\";\nunion I, N\n| summarize SignIns = count(), Success = countif(ResultType == \"0\"), Users = dcount(UserPrincipalName), Days = dcount(bin(TimeGenerated, 1d)),\n            Countries = make_set(tostring(Loc.countryOrRegion)), Risk = make_set(RiskLevelDuringSignIn), Managed = countif(tostring(Dev.isManaged) == \"true\"), Compliant = countif(tostring(Dev.isCompliant) == \"true\"),\n            NamedLoc = make_set(tostring(column_ifexists(\"NetworkLocationDetails\", \"\")), 3) by T",
        "read": "Many users, high success, one country, managed/compliant devices and a trusted named location = corporate egress IP."
      },
      {
        "ctx": "Firewall sessions involving the IP (IPsec tunnel vs. exfiltration)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago(2d)\n| where SourceIP == \"{{IP}}\" or DestinationIP == \"{{IP}}\"\n| summarize Sessions = count(), BytesSent = sum(SentBytes), BytesRecv = sum(ReceivedBytes), Ports = make_set(DestinationPort, 10), Apps = make_set(ApplicationProtocol, 10), Actions = make_set(DeviceAction, 5), Devices = make_set(DeviceName, 3)\n  by SourceIP, DestinationIP, DeviceProduct\n| order by Sessions desc\n| take 10",
        "read": "UDP 500/4500 or ESP between two firewalls is a site-to-site VPN tunnel. Large outbound bytes to unusual ports is not."
      }
    ],
    "fp": "Corporate office egress IPs and site-to-site VPN peers that also appear in threat feeds or 'unusual IP' rules."
  },
  {
    "id": "priv-role-assigned",
    "name": "User assigned a new privileged role (Entra ID / PIM)",
    "cat": "Identity",
    "src": "Entra ID (Sentinel AuditLogs / SigninLogs)",
    "sev": "high",
    "mitre": [
      "T1098.003"
    ],
    "playbook": true,
    "summary": "An account received a privileged directory role. Find who assigned which role and whether through PIM, whether this is routine for the account, and whether either account behaved unusually.",
    "steps": [
      {
        "ctx": "Role assignment details (who, which role, to whom, from where, PIM?)",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where OperationName has_any (\"Add member to role\", \"Add eligible member to role\", \"Add scoped member to role\", \"Add member to role completed (PIM activation)\", \"Add member to role in PIM completed\")\n| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),\n         ActorIP = tostring(InitiatedBy.user.ipAddress),\n         TargetUser = tostring(TargetResources[0].userPrincipalName),\n         Role = tostring(TargetResources[0].modifiedProperties[1].newValue),\n         Justification = tostring(AdditionalDetails)\n| project TimeGenerated, OperationName, Result, Actor, ActorIP, TargetUser, Role, LoggedByService, Justification, CorrelationId\n| order by TimeGenerated asc",
        "read": "<b>PIM activation</b> with a justification is a planned elevation. A direct permanent assignment from an unusual actor or IP is the risk. A Microsoft service IP as ActorIP is normal for PIM."
      },
      {
        "ctx": "Role assignment history (30 days): routine or new?",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where OperationName has \"role\"\n| extend Actor = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)),\n         TargetUser = tostring(TargetResources[0].userPrincipalName),\n         Role = tostring(TargetResources[0].modifiedProperties[1].newValue)\n| where isnotempty(TargetUser)\n| summarize Count = count(), First = min(TimeGenerated), Last = max(TimeGenerated), Ops = make_set(OperationName, 5), Roles = make_set(Role, 5) by Actor, TargetUser\n| order by Last desc",
        "read": "The same account activating the same role regularly is routine PIM use."
      },
      {
        "ctx": "Actor and target sign-ins around the assignment (location, MFA, risk)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName in~ (\"{{ACTOR}}\", \"{{UPN}}\")\n| summarize n = count(), fail = countif(ResultType != \"0\"), IPs = make_set(IPAddress, 5), Countries = make_set(tostring(LocationDetails.countryOrRegion)),\n            MFA = make_set(AuthenticationRequirement), Risk = make_set(RiskLevelDuringSignIn), Apps = make_set(AppDisplayName, 5) by UserPrincipalName",
        "read": "Put the assigner in <b>Actor</b> and the account that got the role in <b>User (UPN)</b>. Both should sign in from expected places with MFA and no risk."
      },
      {
        "ctx": "What the newly privileged account did afterwards",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where tostring(InitiatedBy.user.userPrincipalName) =~ \"{{UPN}}\"\n| summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by OperationName, Result\n| order by n desc",
        "read": "New users, role assignments, app consents, CA or MFA changes right after the elevation are the escalation trigger."
      }
    ],
    "fp": "Planned PIM activations by admins, and onboarding of new admins with a change ticket."
  },
  {
    "id": "pth-ntlm-lateral",
    "name": "AD – Pass-the-Hash NTLM Type 3 lateral movement",
    "cat": "Identity",
    "src": "Windows Security events (Sentinel SecurityEvent) + Defender for Endpoint",
    "sev": "high",
    "mitre": [
      "T1550.002",
      "T1021.002"
    ],
    "playbook": true,
    "summary": "NTLM network logons (Type 3) flagged as possible Pass-the-Hash. Compare with each account's normal pattern and identify the source host to separate routine service or monitoring activity from attacker use of an admin hash.",
    "steps": [
      {
        "ctx": "NTLM network logons for the flagged accounts (frequency, outcome, workstation)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| where EventID in (4624, 4625) and LogonType == 3 and AuthenticationPackageName == \"NTLM\"\n| where TargetUserName =~ \"{{ACCOUNT}}\"\n| summarize Events = count(), Success = countif(EventID == 4624), Fail = countif(EventID == 4625), Days = dcount(bin(TimeGenerated, 1d)), First = min(TimeGenerated), Last = max(TimeGenerated),\n            Workstations = make_set(WorkstationName, 5), LmPkg = make_set(LmPackageName, 3)\n  by Account = strcat(TargetDomainName, \"\\\\\", TargetUserName), IpAddress, Computer\n| order by Account asc, Events desc",
        "read": "Put the flagged accounts in <b>Account name</b> (comma-separated, e.g. Administrator, a monitoring account) and set the look-back to 14d. Daily logons from the same monitoring server are routine; a local or domain Administrator logging on from a workstation is not."
      },
      {
        "ctx": "Source host identity and admin history (30 days)",
        "kql": "union isfuzzy=true\n(SecurityEvent | where TimeGenerated > ago({{BASELINE}}) | where EventID == 4624 and TargetUserName =~ \"{{ACCOUNT}}\" and IpAddress == \"{{INTIP}}\"\n | summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated), Days = dcount(bin(TimeGenerated, 1d)) by Src = \"AdminLogons_30d\", Detail = strcat(Computer, \" LT\", LogonType, \" \", AuthenticationPackageName)),\n(DeviceInfo | where Timestamp > ago({{BASELINE}}) | where DeviceName has \"{{DEVICE}}\" | summarize n = count(), First = min(Timestamp), Last = max(Timestamp), Days = dcount(bin(Timestamp, 1d)) by Src = \"MDE_Device\", Detail = strcat(DeviceName, \" | \", OSPlatform, \" | \", OnboardingStatus)),\n(DeviceNetworkInfo | where Timestamp > ago(7d) | mv-expand ip = parse_json(IPAddresses) | where tostring(ip.IPAddress) == \"{{INTIP}}\" | summarize n = count(), First = min(Timestamp), Last = max(Timestamp), Days = dcount(bin(Timestamp, 1d)) by Src = \"IP_Owner\", Detail = DeviceName),\n(SecurityEvent | where TimeGenerated > ago({{BASELINE}}) | where EventID == 4625 and IpAddress == \"{{INTIP}}\" | summarize n = count(), First = min(TimeGenerated), Last = max(TimeGenerated), Days = dcount(bin(TimeGenerated, 1d)) by Src = \"FailedFromIP\", Detail = strcat(TargetDomainName, \"\\\\\", TargetUserName))\n| order by Src",
        "read": "Put the source IP in <b>Internal IP</b>, the source host in <b>Device name</b> and the admin account in <b>Account name</b>. If the host has used that account every day for 30 days, it is a configured service; a recent first appearance, or a host not onboarded to MDE, needs escalation."
      }
    ],
    "fp": "Monitoring and backup tools that authenticate with NTLM to many servers, and legacy applications configured with an admin account."
  }
];
