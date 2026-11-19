// SOC Triage Query Hub: alert library.
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
        "ctx": "Sign-ins by country with the IPs used (baseline window, 30 days)",
        "kql": "SigninLogs\n| where TimeGenerated >= ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| summarize\n    SignInCount = count(),\n    IPs = make_set(IPAddress, 100)\nby Country\n| extend IPCount = array_length(IPs)\n| project Country, SignInCount, IPCount, IPs\n| order by SignInCount desc",
        "read": "One row per country: how many successful sign-ins, how many IPs, and the IPs themselves. The user's home country should have most sign-ins. A country with only a few sign-ins from one or two IPs is the one to check: look those IPs up in the OSINT tab and compare the times with the full sign-in log in step 2."
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
    "cat": "Firewall",
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
    "cat": "Firewall",
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
    "cat": "Web & proxy",
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
    "cat": "Web & proxy",
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
    "cat": "Firewall",
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
    "cat": "Firewall",
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
  },
  {
    "id": "linux-suspicious-activity",
    "name": "Linux server: suspicious commands, reverse shells and new users (MDE)",
    "cat": "Linux",
    "src": "Microsoft Defender XDR (Advanced hunting)",
    "sev": "medium",
    "mitre": [
      "T1059.004",
      "T1105",
      "T1136.001"
    ],
    "playbook": true,
    "summary": "Linux hosts onboarded to Defender for Endpoint: download-and-execute, reverse shells, cron/user changes and sudo use.",
    "steps": [
      {
        "ctx": "Download-and-execute and reverse-shell patterns",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ProcessCommandLine has_any (\"curl \", \"wget \", \"/dev/tcp/\", \"nc -e\", \"ncat \", \"bash -i\", \"base64 -d\", \"chmod +x\", \"python -c\", \"mkfifo\")\n| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine\n| order by Timestamp desc",
        "read": "curl|wget piped into sh, /dev/tcp/ and nc -e are reverse shells or droppers. A web server user (www-data, nginx, apache) running them means the web app was exploited."
      },
      {
        "ctx": "New users, sudoers and cron changes",
        "kql": "DeviceProcessEvents\n| where Timestamp > ago({{BASELINE}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where FileName in~ (\"useradd\", \"adduser\", \"usermod\", \"passwd\", \"crontab\", \"visudo\") or ProcessCommandLine has_any (\"/etc/sudoers\", \"/etc/cron\", \"authorized_keys\")\n| project Timestamp, DeviceName, AccountName, ProcessCommandLine\n| order by Timestamp desc",
        "read": "Persistence on Linux: new users, keys added to authorized_keys, cron jobs and sudoers edits."
      }
    ],
    "fp": "Configuration management (Ansible, Puppet, Chef) and admins doing maintenance."
  },
  {
    "id": "defender-threat-intel-match",
    "name": "Threat intel: hunt a list of IoCs (IPs, domains, hashes) across Defender",
    "cat": "Threat intel",
    "src": "Microsoft Defender XDR (Advanced hunting)",
    "sev": "medium",
    "mitre": [
      "T1071",
      "T1105"
    ],
    "playbook": true,
    "summary": "Match lists of IoC IPs and hashes from a threat report against network, file and email data.",
    "steps": [
      {
        "ctx": "IoC IPs: network connections and sign-ins",
        "kql": "let IOCs = dynamic([{{IPS}}]);\nunion isfuzzy=true\n    (DeviceNetworkEvents | where Timestamp > ago({{BASELINE}}) | where RemoteIP in (IOCs) | project Timestamp, Source = \"Network\", DeviceName, Account = InitiatingProcessAccountName, IOC = RemoteIP, Detail = InitiatingProcessFileName),\n    (EntraIdSignInEvents | where Timestamp > ago({{BASELINE}}) | where IPAddress in (IOCs) | project Timestamp, Source = \"Sign-in\", DeviceName, Account = AccountUpn, IOC = IPAddress, Detail = Application)\n| order by Timestamp desc",
        "read": "Put the IoC IPs comma-separated in IP addresses. A connection that was allowed, or a successful sign-in, is the escalation case."
      },
      {
        "ctx": "IoC hash: files, processes and email attachments",
        "kql": "union isfuzzy=true DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents, EmailAttachmentInfo\n| where Timestamp > ago({{BASELINE}})\n| where SHA256 in~ (\"{{SHA256}}\")\n| project Timestamp, Type, DeviceName, FileName, FolderPath, SHA256, RecipientEmailAddress\n| order by Timestamp desc",
        "read": "Put several hashes comma-separated in File SHA-256."
      }
    ],
    "fp": "Shared hosting / CDN IPs in threat reports."
  },
  {
    "id": "sentinel-workspace-overview",
    "name": "Sentinel workspace overview: which tables have data?",
    "cat": "SIEM health",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Start here when you join a new client workspace: which log tables are populated, how much data each sends, which agents are reporting, and which alerts fire most.",
    "steps": [
      {
        "ctx": "Which tables have data, and how much? (look-back window)",
        "kql": "Usage\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize GB = round(sum(Quantity) / 1024, 3), Billable = max(IsBillable), LastSeen = max(TimeGenerated) by DataType\n| order by GB desc",
        "read": "Every row is a table that received data. Missing expected tables (e.g. SecurityEvent, Syslog, CommonSecurityLog) means that source isn't connected. Use the table's own entry in this category to explore it."
      },
      {
        "ctx": "Tables that stopped sending data (seen in the baseline, not in the last day)",
        "kql": "Usage\n| where TimeGenerated > ago({{BASELINE}})\n| summarize LastSeen = max(TimeGenerated) by DataType\n| where LastSeen < ago(1d)\n| order by LastSeen asc",
        "read": "Each row is a log source that went quiet. Check the connector, agent or forwarder before trusting any 'no results' from that table."
      },
      {
        "ctx": "Most frequent alerts in the workspace (look-back window)",
        "kql": "SecurityAlert\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Alerts = count(), Entities = dcount(CompromisedEntity), Last = max(TimeGenerated) by AlertName, ProviderName, AlertSeverity\n| order by Alerts desc\n| take 30",
        "read": "The noisiest rules are tuning candidates; check whether their playbook entry exists here."
      },
      {
        "ctx": "Open incidents by severity and owner",
        "kql": "SecurityIncident\n| where TimeGenerated > ago({{BASELINE}})\n| summarize arg_max(TimeGenerated, *) by IncidentNumber\n| where Status != \"Closed\"\n| project IncidentNumber, Title, Severity, Status, Owner = tostring(Owner.assignedTo), CreatedTime, LastModifiedTime\n| order by Severity asc, CreatedTime asc",
        "read": "SecurityIncident keeps a row per update, so arg_max takes the latest state of each incident."
      }
    ],
    "fp": "Reference entry for exploring a workspace, not an alert.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-signinlogs",
    "name": "Sentinel log sample: SigninLogs (Entra ID interactive sign-ins)",
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Interactive Entra ID sign-ins (user typed a password, used MFA, etc.). The main table for identity investigations.",
    "steps": [
      {
        "ctx": "Sample rows: the latest SigninLogs events (look-back window)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType, ResultDescription, Country = tostring(LocationDetails.countryOrRegion), ClientAppUsed, ConditionalAccessStatus, AuthenticationRequirement",
        "read": "Shows what a SigninLogs record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in SigninLogs (schema)",
        "kql": "SigninLogs\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in SigninLogs (look-back window)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by ResultType, ResultDescription\n| order by Events desc\n| take 25",
        "read": "ResultType 0 is success. 50126 bad password, 50053 locked or malicious IP, 50074/50076 routine MFA prompts, 53003 blocked by Conditional Access."
      },
      {
        "ctx": "Daily volume of SigninLogs (baseline window): gaps or spikes?",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "All sign-ins for one user (look-back window)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| project TimeGenerated, AppDisplayName, IPAddress, ResultType, ResultDescription, Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city), ClientAppUsed, AuthenticationRequirement, ConditionalAccessStatus\n| order by TimeGenerated desc",
        "read": "Put the user in User (UPN). Look for failures followed by a success, new countries, or legacy ClientAppUsed values (IMAP, POP, SMTP)."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-aadnoninteractiveusersigninlogs",
    "name": "Sentinel log sample: AADNonInteractiveUserSignInLogs (token refreshes)",
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Sign-ins the user didn't type: apps and mail clients refreshing tokens. Very high volume; key for token-theft and mailbox-access questions.",
    "steps": [
      {
        "ctx": "Sample rows: the latest AADNonInteractiveUserSignInLogs events (look-back window)",
        "kql": "AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, ResultType, Country = tostring(parse_json(LocationDetails).countryOrRegion), ClientAppUsed, UserAgent",
        "read": "Shows what a AADNonInteractiveUserSignInLogs record looks like in this workspace. No rows means the connector isn't sending data (check the volume step). LocationDetails is a string here, so use parse_json() before reading fields."
      },
      {
        "ctx": "Columns in AADNonInteractiveUserSignInLogs (schema)",
        "kql": "AADNonInteractiveUserSignInLogs\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in AADNonInteractiveUserSignInLogs (look-back window)",
        "kql": "AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by AppDisplayName, ResultType\n| order by Events desc\n| take 25",
        "read": "The most common event types are usually routine. Rare types near the bottom are often the interesting ones."
      },
      {
        "ctx": "Daily volume of AADNonInteractiveUserSignInLogs (baseline window): gaps or spikes?",
        "kql": "AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Non-interactive sign-ins for one user, grouped by IP (look-back window)",
        "kql": "AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| summarize Events = count(), Apps = make_set(AppDisplayName, 10), First = min(TimeGenerated), Last = max(TimeGenerated) by IPAddress, Country = tostring(parse_json(LocationDetails).countryOrRegion)\n| order by Last desc",
        "read": "An IP or country the user never uses interactively, refreshing tokens for mail apps, can mean a stolen token."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-auditlogs",
    "name": "Sentinel log sample: AuditLogs (Entra ID directory changes)",
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Entra ID directory changes: users, groups, roles, apps, MFA methods, Conditional Access policies.",
    "steps": [
      {
        "ctx": "Sample rows: the latest AuditLogs events (look-back window)",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, OperationName, Category, Result, Initiator = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), Target = tostring(TargetResources[0].displayName), LoggedByService",
        "read": "Shows what a AuditLogs record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in AuditLogs (schema)",
        "kql": "AuditLogs\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in AuditLogs (look-back window)",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by OperationName, Category\n| order by Events desc\n| take 25",
        "read": "Routine: 'Update user', group membership by sync. Worth a look: role assignments, new MFA methods, consent to apps, Conditional Access changes."
      },
      {
        "ctx": "Daily volume of AuditLogs (baseline window): gaps or spikes?",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Changes made by or to one user (look-back window)",
        "kql": "AuditLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where tostring(InitiatedBy) has \"{{UPN}}\" or tostring(TargetResources) has \"{{UPN}}\"\n| project TimeGenerated, OperationName, Result, Initiator = coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName)), Target = tostring(TargetResources[0].userPrincipalName), TargetName = tostring(TargetResources[0].displayName)\n| order by TimeGenerated desc",
        "read": "Put the user in User (UPN). New authentication methods or roles right after an unusual sign-in suggest account takeover."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-securityevent",
    "name": "Sentinel log sample: SecurityEvent (Windows Security events)",
    "cat": "Endpoint",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Windows Security event log from servers and workstations (logons, process creation, account changes) via the AMA / legacy agent.",
    "steps": [
      {
        "ctx": "Sample rows: the latest SecurityEvent events (look-back window)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, Computer, EventID, Activity, Account, TargetUserName, LogonType, IpAddress, WorkstationName",
        "read": "Shows what a SecurityEvent record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in SecurityEvent (schema)",
        "kql": "SecurityEvent\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in SecurityEvent (look-back window)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by EventID, Activity\n| order by Events desc\n| take 25",
        "read": "Common IDs: 4624 logon, 4625 failed logon, 4688 process created, 4720 user created, 4728/4732/4756 added to group, 4740 locked out, 1102 log cleared."
      },
      {
        "ctx": "Daily volume of SecurityEvent (baseline window): gaps or spikes?",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Security events for one host (look-back window)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Computer startswith \"{{DEVICE}}\"\n| summarize Events = count(), Accounts = make_set(TargetUserName, 20), First = min(TimeGenerated), Last = max(TimeGenerated) by EventID, Activity\n| order by Events desc",
        "read": "Put the host in Device name. 1102 (log cleared), 4720 or group additions on a server are high priority."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-syslog",
    "name": "Sentinel log sample: Syslog (Linux hosts)",
    "cat": "Linux",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Linux syslog: SSH and sudo (auth / authpriv), cron, kernel and daemon messages.",
    "steps": [
      {
        "ctx": "Sample rows: the latest Syslog events (look-back window)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, Computer, HostIP, Facility, SeverityLevel, ProcessName, SyslogMessage",
        "read": "Shows what a Syslog record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in Syslog (schema)",
        "kql": "Syslog\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in Syslog (look-back window)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by Facility, ProcessName\n| order by Events desc\n| take 25",
        "read": "auth/authpriv with sshd or sudo are the security-relevant messages; see the SSH brute-force entry for detailed queries."
      },
      {
        "ctx": "Daily volume of Syslog (baseline window): gaps or spikes?",
        "kql": "Syslog\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Syslog messages for one host (look-back window)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Computer startswith \"{{DEVICE}}\"\n| summarize Events = count(), Sample = take_any(SyslogMessage), Last = max(TimeGenerated) by Facility, ProcessName\n| order by Events desc",
        "read": "Put the Linux host in Device name."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-commonsecuritylog",
    "name": "Sentinel log sample: CommonSecurityLog (firewalls / proxies via CEF)",
    "cat": "Firewall",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Firewall, proxy and network appliance logs in CEF format (Fortinet, Palo Alto, Check Point, etc.).",
    "steps": [
      {
        "ctx": "Sample rows: the latest CommonSecurityLog events (look-back window)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, DeviceVendor, DeviceProduct, Activity, SourceIP, DestinationIP, DestinationPort, ApplicationProtocol, DeviceAction, SentBytes, ReceivedBytes",
        "read": "Shows what a CommonSecurityLog record looks like in this workspace. No rows means the connector isn't sending data (check the volume step). Vendor-specific fields often sit in AdditionalExtensions as key=value pairs; extract() them."
      },
      {
        "ctx": "Columns in CommonSecurityLog (schema)",
        "kql": "CommonSecurityLog\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in CommonSecurityLog (look-back window)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by DeviceVendor, DeviceProduct, DeviceAction\n| order by Events desc\n| take 25",
        "read": "The most common event types are usually routine. Rare types near the bottom are often the interesting ones."
      },
      {
        "ctx": "Daily volume of CommonSecurityLog (baseline window): gaps or spikes?",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Firewall sessions for one IP, either direction (look-back window)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where SourceIP == \"{{IP}}\" or DestinationIP == \"{{IP}}\"\n| summarize Sessions = count(), BytesOut = sum(SentBytes), BytesIn = sum(ReceivedBytes), Ports = make_set(DestinationPort, 20), Actions = make_set(DeviceAction, 5), First = min(TimeGenerated), Last = max(TimeGenerated) by SourceIP, DestinationIP, DeviceProduct\n| order by Sessions desc",
        "read": "Put the IP in IP address. Large BytesOut from an internal host to one external IP is the exfiltration pattern."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-officeactivity",
    "name": "Sentinel log sample: OfficeActivity (Exchange, SharePoint, OneDrive, Teams)",
    "cat": "Email",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Microsoft 365 audit: mailbox actions, inbox rules, file access and sharing, Teams.",
    "steps": [
      {
        "ctx": "Sample rows: the latest OfficeActivity events (look-back window)",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, OfficeWorkload, RecordType, Operation, UserId, ClientIP, OfficeObjectId",
        "read": "Shows what a OfficeActivity record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in OfficeActivity (schema)",
        "kql": "OfficeActivity\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in OfficeActivity (look-back window)",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by OfficeWorkload, Operation\n| order by Events desc\n| take 25",
        "read": "High-value operations: New-InboxRule / Set-InboxRule / UpdateInboxRules, Set-Mailbox (forwarding), Add-MailboxPermission, FileDownloaded at volume, AnonymousLinkCreated."
      },
      {
        "ctx": "Daily volume of OfficeActivity (baseline window): gaps or spikes?",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Microsoft 365 activity for one user (look-back window)",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserId =~ \"{{UPN}}\"\n| summarize Events = count(), IPs = make_set(ClientIP, 10), First = min(TimeGenerated), Last = max(TimeGenerated) by OfficeWorkload, Operation\n| order by Events desc",
        "read": "Put the user in User (UPN). For inbox rules and forwarding detail, use the mailbox and account audit entry."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-azureactivity",
    "name": "Sentinel log sample: AzureActivity (Azure subscription operations)",
    "cat": "Cloud infra",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Azure control-plane operations: who created, changed or deleted resources, role assignments and policies.",
    "steps": [
      {
        "ctx": "Sample rows: the latest AzureActivity events (look-back window)",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, CallerIpAddress, ResourceGroup, _ResourceId",
        "read": "Shows what a AzureActivity record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in AzureActivity (schema)",
        "kql": "AzureActivity\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in AzureActivity (look-back window)",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by OperationNameValue, ActivityStatusValue\n| order by Events desc\n| take 25",
        "read": "Watch for ROLEASSIGNMENTS/WRITE, deletes (…/DELETE), key vault access policy changes and diagnostic settings being removed."
      },
      {
        "ctx": "Daily volume of AzureActivity (baseline window): gaps or spikes?",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Azure operations by one caller (look-back window)",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Caller =~ \"{{UPN}}\"\n| summarize Operations = count(), IPs = make_set(CallerIpAddress, 10), First = min(TimeGenerated), Last = max(TimeGenerated) by OperationNameValue, ActivityStatusValue\n| order by Operations desc",
        "read": "Put the user (Caller UPN) in User (UPN)."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-securityalert",
    "name": "Sentinel log sample: SecurityAlert (alerts from all products)",
    "cat": "SIEM health",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Every alert raised by Sentinel analytics rules and connected Microsoft security products.",
    "steps": [
      {
        "ctx": "Sample rows: the latest SecurityAlert events (look-back window)",
        "kql": "SecurityAlert\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, AlertName, AlertSeverity, ProviderName, ProductName, CompromisedEntity, Status, SystemAlertId",
        "read": "Shows what a SecurityAlert record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in SecurityAlert (schema)",
        "kql": "SecurityAlert\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in SecurityAlert (look-back window)",
        "kql": "SecurityAlert\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by AlertName, ProviderName\n| order by Events desc\n| take 25",
        "read": "The most common event types are usually routine. Rare types near the bottom are often the interesting ones."
      },
      {
        "ctx": "Daily volume of SecurityAlert (baseline window): gaps or spikes?",
        "kql": "SecurityAlert\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Alerts that mention one entity (user, host or IP) (look-back window)",
        "kql": "SecurityAlert\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Entities has_any (\"{{UPN}}\", \"{{DEVICE}}\", \"{{IP}}\") or CompromisedEntity has_any (\"{{UPN}}\", \"{{DEVICE}}\")\n| project TimeGenerated, AlertName, AlertSeverity, ProviderName, CompromisedEntity, Status, SystemAlertId\n| order by TimeGenerated desc",
        "read": "Fill in any of User (UPN), Device name or IP address; fields you leave empty simply match nothing. Several alerts on the same entity in a short time point to a real incident."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-heartbeat",
    "name": "Sentinel log sample: Heartbeat (agent health)",
    "cat": "SIEM health",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "One row per minute from every connected agent. Use it to confirm a host is reporting before trusting 'no results'.",
    "steps": [
      {
        "ctx": "Sample rows: the latest Heartbeat events (look-back window)",
        "kql": "Heartbeat\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, Computer, OSType, Category, Version, ComputerIP",
        "read": "Shows what a Heartbeat record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in Heartbeat (schema)",
        "kql": "Heartbeat\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in Heartbeat (look-back window)",
        "kql": "Heartbeat\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by OSType, Category\n| order by Events desc\n| take 25",
        "read": "Category shows the agent type (Azure Monitor Agent, Direct Agent, SCOM)."
      },
      {
        "ctx": "Daily volume of Heartbeat (baseline window): gaps or spikes?",
        "kql": "Heartbeat\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Last heartbeat per host: which agents went silent?",
        "kql": "Heartbeat\n| where TimeGenerated > ago({{BASELINE}})\n| summarize LastHeartbeat = max(TimeGenerated) by Computer, OSType, ComputerIP\n| extend SilentHours = datetime_diff(\"hour\", now(), LastHeartbeat)\n| where SilentHours >= 1\n| order by SilentHours desc",
        "read": "Each row is a host that stopped reporting in the last hour or more. A silent host during an incident may be off, isolated, or tampered with."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-dnsevents",
    "name": "Sentinel log sample: DnsEvents (Windows DNS server)",
    "cat": "DNS",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "DNS queries and answers from Windows DNS servers (DNS connector / AMA). Useful for C2 domains and DNS tunnelling.",
    "steps": [
      {
        "ctx": "Sample rows: the latest DnsEvents events (look-back window)",
        "kql": "DnsEvents\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, Computer, ClientIP, Name, QueryType, IPAddresses, ResultCode",
        "read": "Shows what a DnsEvents record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in DnsEvents (schema)",
        "kql": "DnsEvents\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in DnsEvents (look-back window)",
        "kql": "DnsEvents\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by QueryType, ResultCode\n| order by Events desc\n| take 25",
        "read": "Lots of TXT queries or NXDOMAIN (ResultCode 3) answers to long random subdomains suggests DNS tunnelling or DGA malware."
      },
      {
        "ctx": "Daily volume of DnsEvents (baseline window): gaps or spikes?",
        "kql": "DnsEvents\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Who queried a domain? (look-back window)",
        "kql": "DnsEvents\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Name has \"{{DOMAIN}}\"\n| summarize Queries = count(), Names = make_set(Name, 20), Answers = make_set(IPAddresses, 10), First = min(TimeGenerated), Last = max(TimeGenerated) by ClientIP\n| order by Queries desc",
        "read": "Put the domain in Domain / URL fragment. ClientIP is the internal host that asked; map it to a device in Defender."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-event",
    "name": "Sentinel log sample: Event (Windows non-security logs)",
    "cat": "Endpoint",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Windows System, Application and other channels collected by the agent (services, PowerShell, Defender operational logs if collected).",
    "steps": [
      {
        "ctx": "Sample rows: the latest Event events (look-back window)",
        "kql": "Event\n| where TimeGenerated > ago({{LOOKBACK}})\n| top 20 by TimeGenerated desc\n| project TimeGenerated, Computer, EventLog, Source, EventID, EventLevelName, RenderedDescription",
        "read": "Shows what a Event record looks like in this workspace. No rows means the connector isn't sending data (check the volume step)."
      },
      {
        "ctx": "Columns in Event (schema)",
        "kql": "Event\n| getschema\n| project ColumnName, ColumnType",
        "read": "Lists every column and its type. Use it before writing a new query so column names are exact; dynamic columns (e.g. JSON details) need tostring() or parse_json()."
      },
      {
        "ctx": "Top event types in Event (look-back window)",
        "kql": "Event\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Events = count() by EventLog, Source, EventID\n| order by Events desc\n| take 25",
        "read": "Useful IDs: 7045 new service installed (System), 4104 PowerShell script block (if collected), 1116/1117 Defender detections."
      },
      {
        "ctx": "Daily volume of Event (baseline window): gaps or spikes?",
        "kql": "Event\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Events = count() by Day = bin(TimeGenerated, 1d)\n| order by Day asc",
        "read": "A day with zero or far fewer events means the source stopped logging (connector, agent or firewall problem). A sudden spike may be an attack, a misconfiguration, or a new data source."
      },
      {
        "ctx": "Windows events for one host (look-back window)",
        "kql": "Event\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Computer startswith \"{{DEVICE}}\"\n| summarize Events = count(), Sample = take_any(substring(RenderedDescription, 0, 200)), Last = max(TimeGenerated) by EventLog, Source, EventID\n| order by Events desc",
        "read": "Put the host in Device name. A new service (7045) with a random name or a path in Temp/ProgramData is suspicious."
      }
    ],
    "fp": "Reference entry for exploring a log table, not an alert. Column availability depends on the connector and its version.",
    "platform": "Sentinel"
  },
  {
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-user-signin-investigation",
    "name": "Sentinel: user sign-in investigation (success, IP, devices)",
    "sev": "medium",
    "mitre": [
      "T1078"
    ],
    "summary": "Day-to-day SigninLogs checks for one or more users: successful sign-ins, sign-ins (all or successful only) from a specific IP, the devices used, and the time range seen per location.",
    "steps": [
      {
        "ctx": "Successful sign-ins for the user",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"   // 0 = success\n| project TimeGenerated, UserPrincipalName, AppDisplayName, ResourceDisplayName, IPAddress,\n          Location, City = tostring(LocationDetails.city), ClientAppUsed, UserAgent,\n          DeviceOS = tostring(DeviceDetail.operatingSystem), DeviceBrowser = tostring(DeviceDetail.browser),\n          ResultSignature\n| order by TimeGenerated desc",
        "read": "Several users? Put them comma-separated in User (UPN); the query switches to in~ automatically. ResultType is a string in SigninLogs, so \"0\" is success."
      },
      {
        "ctx": "All sign-in attempts for the user from a specific IP",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where IPAddress == \"{{IP}}\"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResourceDisplayName,\n          ResultType, ResultSignature, ResultDescription, ConditionalAccessStatus, AuthenticationRequirement\n| order by TimeGenerated desc",
        "read": "No success rows (only failures or 50126/50053) means the attempt did not get in. A success with MFA satisfied from an unknown IP needs the user confirmed."
      },
      {
        "ctx": "Successful sign-ins for the user from a specific IP",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where IPAddress == \"{{IP}}\"\n| where ResultType == \"0\"   // 0 = success\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResourceDisplayName, ResultSignature, ResultType\n| order by TimeGenerated desc",
        "read": "Fill User (UPN) and IP. Rows mean the IP really got into the account: confirm with the user, and if it is not theirs revoke sessions and reset the password. No rows = no successful sign-in from that IP in the baseline window."
      },
      {
        "ctx": "Successful sign-ins from the IP across all users",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where IPAddress == \"{{IP}}\"\n| where ResultType == \"0\"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResourceDisplayName, ResultSignature\n| order by TimeGenerated desc",
        "read": "One IP used by many unrelated users is usually an office, VPN or proxy egress; a single unexpected user on a foreign IP is the case to escalate."
      },
      {
        "ctx": "Result breakdown for the IP across all accounts (bar chart)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where IPAddress == \"{{IP}}\"\n| summarize Count = count(), Users = dcount(UserPrincipalName) by ResultSignature, ResultType, ResultDescription\n| order by Count desc\n| render barchart",
        "read": "Mostly failures against many users from one IP is password spraying; check whether any SUCCESS row appears for the same IP."
      },
      {
        "ctx": "Devices and location details behind the user's successful sign-ins",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Device = parse_json(tostring(DeviceDetail)), Loc = parse_json(tostring(LocationDetails)), Stat = parse_json(tostring(Status))\n| project TimeGenerated, UserPrincipalName, App = ResourceDisplayName, ResultType, ResultDescription,\n          StatusErrorCode = toint(Stat.errorCode), StatusDetails = tostring(Stat.additionalDetails), IPAddress,\n          DeviceName = tostring(Device.displayName), DeviceOS = tostring(Device.operatingSystem),\n          DeviceBrowser = tostring(Device.browser), DeviceId = tostring(Device.deviceId),\n          TrustType = tostring(Device.trustType), IsCompliant = tostring(Device.isCompliant), IsManaged = tostring(Device.isManaged),\n          City = tostring(Loc.city), State = tostring(Loc.state), CountryOrRegion = tostring(Loc.countryOrRegion),\n          Latitude = toreal(Loc.geoCoordinates.latitude), Longitude = toreal(Loc.geoCoordinates.longitude)\n| order by TimeGenerated desc",
        "read": "An empty DeviceId and TrustType means an unregistered device. TrustType 'Azure AD registered' is a personal (BYOD) device, 'Azure AD joined' or 'Hybrid Azure AD joined' is corporate."
      },
      {
        "ctx": "Time range seen per location (first and last sign-in)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| summarize Count = count(), StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), IPs = make_set(IPAddress, 50)\n    by Location = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)\n| extend Timeframe = strcat(format_datetime(StartTime, 'yyyy-MM-dd HH:mm:ss'), ' to ', format_datetime(EndTime, 'yyyy-MM-dd HH:mm:ss'))\n| order by Count desc",
        "read": "Paste the Timeframe column straight into the ticket. Two countries whose time ranges overlap is impossible travel unless one is a VPN."
      }
    ],
    "fp": "VPN and mobile carrier IPs geolocate to odd cities; travelling users. Confirm with the user or manager before closing as malicious.",
    "platform": "Sentinel"
  },
  {
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-signin-locations",
    "name": "Sentinel: sign-in locations (map and outside home country)",
    "sev": "medium",
    "mitre": [
      "T1078"
    ],
    "summary": "Show where users signed in from on a map, and list or chart successful sign-ins outside the client's home country.",
    "steps": [
      {
        "ctx": "Successful sign-in locations on a map (one or more users)",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Latitude = toreal(LocationDetails.geoCoordinates.latitude), Longitude = toreal(LocationDetails.geoCoordinates.longitude)\n| summarize Count = count() by UserPrincipalName, Latitude, Longitude,\n    Location = tostring(LocationDetails.city), Country = tostring(LocationDetails.countryOrRegion)\n| render scatterchart with (kind=map)",
        "read": "Put several users comma-separated in User (UPN) to see them on one map. Coordinates live under LocationDetails.geoCoordinates. The map renders in the Sentinel Logs blade; switch to Results for the table."
      },
      {
        "ctx": "Successful sign-ins outside the home countries",
        "kql": "let Home = dynamic([{{COUNTRIES}}]);\nSigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion), City = tostring(LocationDetails.city), State = tostring(LocationDetails.state)\n| where isnotempty(Country) and Country !in~ (Home)\n| project TimeGenerated, UserPrincipalName, IPAddress, City, State, Country, AppDisplayName, ResultSignature, ResultDescription, UserAgent\n| order by TimeGenerated desc",
        "read": "Put the client's home country codes in Countries (e.g. AU). No rows = all successful sign-ins were in the home countries."
      },
      {
        "ctx": "Outside the home countries by country (bar chart)",
        "kql": "let Home = dynamic([{{COUNTRIES}}]);\nSigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| where ResultType == \"0\"\n| extend Country = tostring(LocationDetails.countryOrRegion)\n| where isnotempty(Country) and Country !in~ (Home)\n| summarize Count = count() by Country\n| order by Count desc\n| render barchart",
        "read": "A single country with a handful of sign-ins is typical of travel or VPN; many countries in a short window is a stronger compromise signal."
      }
    ],
    "fp": "Travel, corporate VPN egress abroad, and Microsoft/carrier IPs with wrong geolocation.",
    "platform": "Sentinel"
  },
  {
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-bad-useragent",
    "name": "Attempted Authentication from Known-Bad UserAgent",
    "sev": "medium",
    "mitre": [
      "T1078",
      "T1110"
    ],
    "summary": "Check the HTTP user agent in the sign-in, whether the client was a browser, mobile app or desktop client, and whether the device is Entra (Azure AD) registered.",
    "steps": [
      {
        "ctx": "The user's sign-ins with user agent, client and device trust",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ClientAppUsed, UserAgent,\n          DeviceBrowser = tostring(DeviceDetail.browser), DeviceOS = tostring(DeviceDetail.operatingSystem),\n          DeviceName = tostring(DeviceDetail.displayName), TrustType = tostring(DeviceDetail.trustType),\n          IsCompliant = tostring(DeviceDetail.isCompliant), ResultType, ResultDescription\n| order by TimeGenerated desc",
        "read": "Check: HTTP User Agent (UserAgent), Device Browser (ClientAppUsed 'Browser' vs 'Mobile Apps and Desktop clients'), Device Status (TrustType 'Azure AD registered' / joined). Tools such as python-requests, curl, Go-http-client or axios against a user account are not normal clients."
      },
      {
        "ctx": "Everyone who used the same user agent",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where UserAgent has \"{{USERAGENT}}\"\n| summarize Attempts = count(), Successes = countif(ResultType == \"0\"), IPs = make_set(IPAddress, 50), Last = max(TimeGenerated)\n    by UserPrincipalName, AppDisplayName\n| order by Attempts desc",
        "read": "Put a distinctive part of the user agent in User agent. Many users with only failures is spraying; any Successes row needs the session revoked and password reset."
      },
      {
        "ctx": "Non-interactive sign-ins with the same user agent",
        "kql": "AADNonInteractiveUserSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\" or UserAgent has \"{{USERAGENT}}\"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, UserAgent, ResultType, ResultDescription\n| order by TimeGenerated desc",
        "read": "Token replay and scripted access often appear only in non-interactive logs."
      }
    ],
    "fp": "Legitimate scripts, migration tools and some mail clients use generic user agents; check with the client before blocking.",
    "platform": "Sentinel"
  },
  {
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-service-principal-signins",
    "name": "Sentinel: service principal sign-ins",
    "sev": "medium",
    "mitre": [
      "T1078.004"
    ],
    "summary": "Check sign-ins by an app registration / service principal: successful logins from an IP, and its daily pattern by location.",
    "steps": [
      {
        "ctx": "Successful service principal sign-ins from the IP",
        "kql": "AADServicePrincipalSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ServicePrincipalName == \"{{SPN}}\"\n| where IPAddress == \"{{IP}}\"\n| where ResultType == \"0\"\n| project TimeGenerated, ServicePrincipalName, ServicePrincipalId, AppId, IPAddress, Location, ResourceDisplayName, ResultType\n| order by TimeGenerated desc",
        "read": "Put the app's display name in Service principal name. Check the IP owner in OSINT: Microsoft or the vendor's cloud is expected, residential or VPS hosting is not."
      },
      {
        "ctx": "Daily sign-ins by location (baseline)",
        "kql": "AADServicePrincipalSignInLogs\n| where TimeGenerated > ago({{BASELINE}})\n| where ServicePrincipalName == \"{{SPN}}\"\n| summarize Count = count() by bin(TimeGenerated, 1d), ServicePrincipalName, Location, ResultType\n| order by TimeGenerated asc",
        "read": "A service principal normally signs in from the same few locations every day; a new country on the alert date is the anomaly."
      },
      {
        "ctx": "New IPs for the service principal compared with the baseline",
        "kql": "let Known = AADServicePrincipalSignInLogs\n    | where TimeGenerated between (ago({{BASELINE}}) .. ago({{LOOKBACK}}))\n    | where ServicePrincipalName == \"{{SPN}}\"\n    | distinct IPAddress;\nAADServicePrincipalSignInLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ServicePrincipalName == \"{{SPN}}\"\n| where IPAddress !in (Known)\n| summarize Count = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by IPAddress, Location, ResourceDisplayName",
        "read": "Each row is an IP the app never used during the baseline window."
      }
    ],
    "fp": "Vendor platform moves between cloud regions; credential rotation.",
    "platform": "Sentinel"
  },
  {
    "cat": "Identity",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-identityinfo-lookup",
    "name": "Sentinel: user details lookup (IdentityInfo wildcard search)",
    "sev": "info",
    "mitre": [],
    "summary": "Find a user's job title, department, country, manager and status when you only know part of the UPN or name.",
    "steps": [
      {
        "ctx": "Latest identity record for the user (partial match)",
        "kql": "IdentityInfo\n| where TimeGenerated > ago(14d)\n| where AccountUPN contains \"{{UPN}}\" or AccountName contains \"{{ACCOUNT}}\"\n| summarize arg_max(TimeGenerated, *) by AccountUPN\n| project AccountUPN, AccountDisplayName, JobTitle, Department, Country, City, Manager, IsAccountEnabled, AssignedRoles, Tags, RiskLevel",
        "read": "IdentityInfo is refreshed every 14 days, so look back at least that far. contains is a partial (wildcard) match; leave Account name empty if you only have the UPN."
      }
    ],
    "fp": "Reference lookup.",
    "platform": "Sentinel"
  },
  {
    "cat": "Network",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-malicious-ip-traffic",
    "name": "Sentinel: traffic to or from a detected malicious IP",
    "sev": "medium",
    "mitre": [
      "T1071",
      "T1190"
    ],
    "summary": "For 'A network session source address…', exploitation traffic and threat-intel IP alerts: check endpoint connections, DNS events and firewall logs for the IP.",
    "steps": [
      {
        "ctx": "Endpoint connections to the IP (Defender table in Sentinel)",
        "kql": "DeviceNetworkEvents\n| where TimeGenerated > ago({{BASELINE}})\n| where RemoteIP == \"{{IP}}\"\n| project TimeGenerated, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessAccountName, LocalIP, RemoteIP, RemotePort, Protocol, ReportId\n| order by TimeGenerated desc",
        "read": "Defender tables streamed into Sentinel use TimeGenerated. ConnectionSuccess means traffic actually left the host; no rows means no endpoint talked to it."
      },
      {
        "ctx": "DNS events mentioning the IP",
        "kql": "DnsEvents\n| where TimeGenerated > ago({{BASELINE}})\n| where IPAddresses has \"{{IP}}\" or ClientIP == \"{{IP}}\"\n| project TimeGenerated, Computer, ClientIP, Name, IPAddresses, QueryType, ResultCode\n| order by TimeGenerated desc",
        "read": "No rows: 'There are no outbound network traffic on the detected malicious IP address in the DNS Event. No further action required.'"
      },
      {
        "ctx": "Firewall / exploitation traffic for the IP (CommonSecurityLog)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{BASELINE}})\n| where SourceIP == \"{{IP}}\" or DestinationIP == \"{{IP}}\"\n| project TimeGenerated, DeviceVendor, DeviceProduct, DeviceEventClassID, Activity, DeviceAction, Reason, SourceIP, DestinationIP, DestinationPort, RequestURL\n| order by TimeGenerated desc",
        "read": "DeviceAction deny/drop/reset means the firewall blocked it. Allowed inbound exploitation traffic to a public server needs the server checked."
      },
      {
        "ctx": "Free-text search for the IP in all firewall fields",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{BASELINE}})\n| search \"{{IP}}\"\n| project TimeGenerated, DeviceVendor, DeviceEventClassID, Activity, DeviceAction, Reason, SourceIP, DestinationIP",
        "read": "search is slower but also finds the IP in AdditionalExtensions and message fields."
      }
    ],
    "fp": "Scanners hitting public IPs constantly; shared CDN or cloud IPs flagged by threat intel.",
    "platform": "Sentinel"
  },
  {
    "cat": "Endpoint",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-file-hash-hunt",
    "name": "Sentinel: file hash mini threat hunt",
    "sev": "medium",
    "mitre": [
      "T1204",
      "T1105"
    ],
    "summary": "Where has a file hash been seen, which hosts have the file, and what archives or executables arrived on a host.",
    "steps": [
      {
        "ctx": "Mini threat hunt: one or more SHA-256 hashes across endpoint and email tables",
        "kql": "union DeviceEvents, DeviceFileEvents, DeviceProcessEvents, EmailAttachmentInfo\n| where TimeGenerated > ago({{BASELINE}})\n| where SHA256 in~ (\"{{SHA256}}\")\n| project TimeGenerated, Type, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName, RecipientEmailAddress, SenderFromAddress\n| order by TimeGenerated desc",
        "read": "Put several hashes comma-separated in File SHA-256; they expand inside the list. Type shows which table matched."
      },
      {
        "ctx": "Hash prevalence (first/last seen and devices)",
        "kql": "DeviceFileEvents\n| where TimeGenerated > ago({{BASELINE}})\n| where SHA256 == \"{{SHA256}}\"\n| summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), DeviceCount = dcount(DeviceName), Devices = make_set(DeviceName, 100) by SHA256",
        "read": "One device = targeted; many devices = software deployment or a campaign."
      },
      {
        "ctx": "The file on a specific host",
        "kql": "DeviceFileEvents\n| where TimeGenerated > ago({{BASELINE}})\n| where DeviceName =~ \"{{DEVICE}}\"\n| where FileName =~ \"{{FILENAME}}\"\n| project TimeGenerated, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName, FileOriginUrl\n| order by TimeGenerated desc",
        "read": "FileOriginUrl and InitiatingProcessFileName (browser, Outlook, 7-Zip) show where the file came from. Check the SHA256 in OSINT."
      },
      {
        "ctx": "Archives and executables written on the host",
        "kql": "DeviceFileEvents\n| where TimeGenerated > ago({{LOOKBACK}})\n| where DeviceName =~ \"{{DEVICE}}\"\n| where FileName endswith \".zip\" or FileName endswith \".exe\" or FileName endswith \".iso\" or FileName endswith \".msi\"\n| project TimeGenerated, ActionType, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessAccountName\n| order by TimeGenerated desc",
        "read": "Look for files in Downloads, Temp or AppData that were extracted from the archive in the alert."
      }
    ],
    "fp": "Installers and updates pushed by IT; known-good files flagged by a single engine.",
    "platform": "Sentinel"
  },
  {
    "cat": "Cloud apps",
    "src": "Microsoft Sentinel (Log Analytics)",
    "playbook": true,
    "id": "sentinel-darktrace-saas",
    "name": "Darktrace Anomalous SaaS Resources detected",
    "sev": "medium",
    "mitre": [
      "T1078.004",
      "T1530"
    ],
    "summary": "Darktrace flagged unusual SaaS resource access. Check the user agent and sign-ins of the account, the caller IP in cloud activity, and whether any endpoint talked to the remote IP.",
    "steps": [
      {
        "ctx": "Account sign-ins with user agent",
        "kql": "SigninLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| where UserPrincipalName =~ \"{{UPN}}\"\n| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResourceDisplayName, UserAgent, ClientAppUsed, ResultType, ResultDescription\n| order by TimeGenerated desc",
        "read": "Compare the IP and user agent with the Darktrace event. A new IP plus a new user agent around the alert time is suspicious."
      },
      {
        "ctx": "SaaS activity by the account and caller IP (Office 365 and Azure)",
        "kql": "union isfuzzy=true\n    (OfficeActivity\n        | where TimeGenerated > ago({{LOOKBACK}})\n        | where UserId =~ \"{{UPN}}\" or ClientIP has \"{{IP}}\"\n        | project TimeGenerated, Source = \"OfficeActivity\", User = UserId, CallerIP = ClientIP, Operation, Workload = OfficeWorkload, Object = OfficeObjectId),\n    (AzureActivity\n        | where TimeGenerated > ago({{LOOKBACK}})\n        | where Caller =~ \"{{UPN}}\" or CallerIpAddress == \"{{IP}}\"\n        | project TimeGenerated, Source = \"AzureActivity\", User = Caller, CallerIP = CallerIpAddress, Operation = OperationNameValue, Workload = ResourceProviderValue, Object = _ResourceId)\n| order by TimeGenerated desc",
        "read": "Bulk downloads (FileDownloaded, FileSyncDownloadedFull) or new sharing links from the caller IP are the resources Darktrace usually flags."
      },
      {
        "ctx": "Endpoint connections to the remote IP",
        "kql": "DeviceNetworkEvents\n| where TimeGenerated > ago({{LOOKBACK}})\n| where RemoteIP == \"{{IP}}\"\n| project TimeGenerated, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, RemoteIP, RemotePort, RemoteUrl, ActionType\n| order by TimeGenerated desc",
        "read": "No rows means no onboarded endpoint connected to the IP."
      }
    ],
    "fp": "New SaaS tools adopted by a team, backup/sync clients, and users on travel or new VPNs.",
    "platform": "Sentinel"
  },
  {
    "id": "sentinel-windows-logon-attacks",
    "name": "Sentinel: Windows brute force and password spraying (SecurityEvent)",
    "cat": "Identity",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1110",
      "T1110.003"
    ],
    "playbook": true,
    "summary": "Failed Windows logons (4625) by account and by source, password spraying, and failures that end in a success (4624).",
    "steps": [
      {
        "ctx": "Repeated failures per account in 15-minute windows",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| where EventID == 4625\n| summarize FailedAttempts = count(), Sources = make_set(IpAddress, 20), Computers = make_set(Computer, 20) by TargetAccount, bin(TimeGenerated, 15m)\n| where FailedAttempts >= 10\n| order by FailedAttempts desc",
        "read": "10+ failures in 15 minutes for one account is brute force. SubStatus 0xC000006A = wrong password, 0xC0000064 = user does not exist."
      },
      {
        "ctx": "One source against many accounts (password spraying)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| where EventID == 4625\n| summarize FailedAttempts = count(), TargetedAccounts = dcount(TargetAccount), Accounts = make_set(TargetAccount, 50) by IpAddress, WorkstationName\n| where TargetedAccounts >= 5\n| order by TargetedAccounts desc",
        "read": "A single IP or workstation failing against 5+ different accounts is spraying. Check the source in OSINT if it is external."
      },
      {
        "ctx": "Failures followed by a success within 30 minutes",
        "kql": "let Failures = SecurityEvent\n    | where TimeGenerated > ago({{LOOKBACK}}) and EventID == 4625\n    | summarize FailedCount = count(), LastFailure = max(TimeGenerated) by TargetAccount, IpAddress, Computer\n    | where FailedCount >= 5;\nlet Successes = SecurityEvent\n    | where TimeGenerated > ago({{LOOKBACK}}) and EventID == 4624\n    | summarize FirstSuccess = min(TimeGenerated) by TargetAccount, IpAddress, Computer;\nFailures\n| join kind=inner Successes on TargetAccount, IpAddress, Computer\n| where FirstSuccess between (LastFailure .. LastFailure + 30m)\n| project TargetAccount, IpAddress, Computer, FailedCount, LastFailure, FirstSuccess",
        "read": "Any row means the password was probably guessed: reset it, check what the account did after FirstSuccess."
      },
      {
        "ctx": "Account lockouts and the calling computer (4740)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{BASELINE}})\n| where EventID == 4740\n| project TimeGenerated, LockedAccount = TargetAccount, CallerComputer = TargetDomainName, DomainController = Computer\n| order by TimeGenerated desc",
        "read": "In 4740 the caller computer (where the bad passwords came from) is stored in TargetDomainName. A stale mapped drive or phone with an old password is the usual benign cause."
      }
    ],
    "fp": "Users with an old password saved on a phone or mapped drive; service accounts after a password change; vulnerability scanners."
  },
  {
    "id": "sentinel-account-changes",
    "name": "Sentinel: account and group changes on Windows / AD (SecurityEvent)",
    "cat": "Identity",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1136.002",
      "T1098",
      "T1078.002"
    ],
    "playbook": true,
    "summary": "New accounts, password resets, privileged group membership changes, privileged and explicit-credential logons.",
    "steps": [
      {
        "ctx": "Accounts created (4720) and password resets (4724)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{BASELINE}})\n| where EventID in (4720, 4724)\n| project TimeGenerated, Activity, TargetAccount, SubjectAccount, Computer\n| order by TimeGenerated desc",
        "read": "SubjectAccount is who did it. Accounts created outside the helpdesk / IAM process, or by a normal user account, need confirming."
      },
      {
        "ctx": "Security group membership changes (privilege escalation)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{BASELINE}})\n| where EventID in (4728, 4729, 4732, 4733, 4756, 4757)\n| project TimeGenerated, Activity, Group = TargetUserName, Member = MemberName, MemberSid, ChangedBy = SubjectAccount, Computer\n| order by TimeGenerated desc",
        "read": "4728/4732/4756 = added, 4729/4733/4757 = removed. Additions to Domain Admins, Enterprise Admins, Administrators or Backup Operators are high priority."
      },
      {
        "ctx": "Privileged logons (4672) and explicit credentials (4648) for the account",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| where EventID in (4672, 4648)\n| where Account has \"{{ACCOUNT}}\" or TargetAccount has \"{{ACCOUNT}}\"\n| project TimeGenerated, Activity, Account, TargetAccount, TargetServerName, Computer, IpAddress, ProcessName\n| order by TimeGenerated desc",
        "read": "4648 (runas / explicit credentials) to many servers from one workstation is a lateral-movement pattern."
      }
    ],
    "fp": "Onboarding and offboarding by IT; group changes from IAM tools; admins using runas."
  },
  {
    "id": "sentinel-suspicious-process",
    "name": "Sentinel: suspicious process and PowerShell activity",
    "cat": "Endpoint",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1059.001",
      "T1027",
      "T1082"
    ],
    "playbook": true,
    "summary": "PowerShell use, encoded commands, discovery commands and rare process or parent-child pairs (Defender tables in Sentinel, or SecurityEvent 4688).",
    "steps": [
      {
        "ctx": "Encoded or download PowerShell",
        "kql": "DeviceProcessEvents\n| where TimeGenerated > ago({{LOOKBACK}})\n| where FileName in~ (\"powershell.exe\", \"pwsh.exe\")\n| where ProcessCommandLine has_any (\"-enc\", \"-encodedcommand\", \"FromBase64String\", \"DownloadString\", \"IEX\", \"Invoke-WebRequest\", \"-w hidden\")\n| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine\n| order by TimeGenerated desc",
        "read": "Defender tables in Sentinel use TimeGenerated. Decode -enc payloads (Base64 UTF-16LE) before deciding. A parent of winword/excel/outlook/mshta is a strong signal."
      },
      {
        "ctx": "Discovery commands on a host",
        "kql": "let SearchTerms = dynamic([\"whoami\", \"net user\", \"net group\", \"net localgroup\", \"nltest\", \"ipconfig /all\", \"systeminfo\", \"quser\", \"arp -a\"]);\nDeviceProcessEvents\n| where TimeGenerated > ago({{LOOKBACK}})\n| where DeviceName startswith \"{{DEVICE}}\"\n| where ProcessCommandLine has_any (SearchTerms)\n| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine\n| order by TimeGenerated asc",
        "read": "Several discovery commands within minutes, from a non-admin user or from a script host, is hands-on-keyboard activity."
      },
      {
        "ctx": "Rare processes and parent-child pairs (environment-wide)",
        "kql": "DeviceProcessEvents\n| where TimeGenerated > ago({{BASELINE}})\n| summarize Executions = count(), Devices = dcount(DeviceName), Example = any(ProcessCommandLine) by InitiatingProcessFileName, FileName\n| where Executions <= 3\n| order by Executions asc",
        "read": "Low-count pairs like excel.exe -> powershell.exe or w3wp.exe -> cmd.exe are hunting leads; most rare pairs are benign installers."
      },
      {
        "ctx": "Process creation from SecurityEvent 4688 (no Defender connector)",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{LOOKBACK}})\n| where EventID == 4688\n| where Computer startswith \"{{DEVICE}}\"\n| project TimeGenerated, Computer, Account, ParentProcessName, NewProcessName, CommandLine\n| order by TimeGenerated desc",
        "read": "CommandLine is only filled if 'Include command line in process creation events' is enabled by GPO."
      }
    ],
    "fp": "Admin and deployment scripts (SCCM, Intune, RMM tools) use encoded PowerShell and discovery commands."
  },
  {
    "id": "sentinel-defense-evasion",
    "name": "Sentinel: audit log cleared and logging tampered",
    "cat": "Endpoint",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "high",
    "mitre": [
      "T1070.001",
      "T1562.002"
    ],
    "playbook": true,
    "summary": "Windows Security log cleared (1102), audit policy changed (4719) and event log service stopped.",
    "steps": [
      {
        "ctx": "Security log cleared or audit policy changed",
        "kql": "SecurityEvent\n| where TimeGenerated > ago({{BASELINE}})\n| where EventID in (1102, 4719)\n| project TimeGenerated, Computer, EventID, Activity, SubjectAccount, SubjectUserName\n| order by TimeGenerated desc",
        "read": "1102 outside a documented maintenance window is high priority: attackers clear logs after acting. Look at what happened on the host just before."
      },
      {
        "ctx": "System log cleared (104) and event log service stopped",
        "kql": "Event\n| where TimeGenerated > ago({{BASELINE}})\n| where (EventLog == \"System\" and EventID == 104) or (Source == \"Service Control Manager\" and RenderedDescription has \"Windows Event Log\")\n| project TimeGenerated, Computer, EventLog, EventID, RenderedDescription\n| order by TimeGenerated desc",
        "read": "Event needs the System log collected by the AMA/MMA data collection rule."
      }
    ],
    "fp": "Re-imaging and documented log maintenance."
  },
  {
    "id": "sentinel-timelines",
    "name": "Sentinel: timeline for one user or one host",
    "cat": "Endpoint",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Put everything a user or a host did in time order across tables, for the incident write-up.",
    "steps": [
      {
        "ctx": "User timeline (sign-ins, Windows events, processes)",
        "kql": "union isfuzzy=true\n    (SigninLogs | where TimeGenerated > ago({{LOOKBACK}}) | where UserPrincipalName =~ \"{{UPN}}\"\n        | project TimeGenerated, Source = \"SigninLogs\", Detail = strcat(AppDisplayName, \" | \", IPAddress, \" | \", ResultType)),\n    (SecurityEvent | where TimeGenerated > ago({{LOOKBACK}}) | where TargetAccount has \"{{ACCOUNT}}\"\n        | project TimeGenerated, Source = \"SecurityEvent\", Detail = strcat(EventID, \" \", Activity, \" | \", Computer)),\n    (DeviceProcessEvents | where TimeGenerated > ago({{LOOKBACK}}) | where AccountName =~ \"{{ACCOUNT}}\"\n        | project TimeGenerated, Source = \"Process\", Detail = strcat(DeviceName, \" | \", ProcessCommandLine)),\n    (OfficeActivity | where TimeGenerated > ago({{LOOKBACK}}) | where UserId =~ \"{{UPN}}\"\n        | project TimeGenerated, Source = \"OfficeActivity\", Detail = strcat(Operation, \" | \", ClientIP))\n| order by TimeGenerated asc",
        "read": "Fill both User (UPN) and Account name. isfuzzy=true skips tables that don't exist in this workspace."
      },
      {
        "ctx": "Host timeline (processes, network, files)",
        "kql": "union isfuzzy=true\n    (DeviceProcessEvents | where TimeGenerated > ago({{LOOKBACK}}) | where DeviceName startswith \"{{DEVICE}}\"\n        | project TimeGenerated, Source = \"Process\", Detail = strcat(AccountName, \" | \", ProcessCommandLine)),\n    (DeviceNetworkEvents | where TimeGenerated > ago({{LOOKBACK}}) | where DeviceName startswith \"{{DEVICE}}\"\n        | project TimeGenerated, Source = \"Network\", Detail = strcat(InitiatingProcessFileName, \" -> \", RemoteIP, \":\", RemotePort, \" \", RemoteUrl)),\n    (DeviceFileEvents | where TimeGenerated > ago({{LOOKBACK}}) | where DeviceName startswith \"{{DEVICE}}\"\n        | project TimeGenerated, Source = \"File\", Detail = strcat(ActionType, \" | \", FolderPath))\n| order by TimeGenerated asc",
        "read": "Narrow the look-back to the hours around the alert; a full day of a busy host is thousands of rows."
      }
    ],
    "fp": "Reference entry."
  },
  {
    "id": "sentinel-mailbox-rules",
    "name": "Sentinel: inbox rules, forwarding and mailbox access (OfficeActivity)",
    "cat": "Email",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1114.003",
      "T1564.008",
      "T1098.002"
    ],
    "playbook": true,
    "summary": "After a suspicious sign-in: did the attacker create inbox rules, set forwarding, give mailbox permissions or read mail?",
    "steps": [
      {
        "ctx": "Inbox rules and forwarding created or changed",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{BASELINE}})\n| where OfficeWorkload == \"Exchange\"\n| where Operation in~ (\"New-InboxRule\", \"Set-InboxRule\", \"UpdateInboxRules\", \"Set-Mailbox\", \"New-TransportRule\")\n| where UserId =~ \"{{UPN}}\"\n| project TimeGenerated, UserId, Operation, ClientIP, Parameters\n| order by TimeGenerated desc",
        "read": "In Parameters look for ForwardTo, RedirectTo, ForwardingSmtpAddress, DeleteMessage, MoveToFolder (RSS Feeds, Archive) and keywords like invoice, payment, password."
      },
      {
        "ctx": "Mailbox permissions granted",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{BASELINE}})\n| where Operation in~ (\"Add-MailboxPermission\", \"Add-RecipientPermission\", \"Add-MailboxFolderPermission\", \"Set-MailboxFolderPermission\")\n| project TimeGenerated, UserId, Operation, ClientIP, Parameters\n| order by TimeGenerated desc",
        "read": "FullAccess or SendAs granted to an unexpected account can hide mailbox takeover."
      },
      {
        "ctx": "Mail items accessed by the user, by IP",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Operation == \"MailItemsAccessed\"\n| where UserId =~ \"{{UPN}}\"\n| summarize Events = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by ClientIP, ClientInfoString\n| order by Events desc",
        "read": "MailItemsAccessed needs audit (Premium) licensing. An unknown IP reading mail after a risky sign-in shows what the attacker could see."
      }
    ],
    "fp": "Users' own organising rules; shared mailbox delegation by IT."
  },
  {
    "id": "sentinel-file-sharing",
    "name": "Sentinel: SharePoint / OneDrive mass download and sharing",
    "cat": "Cloud apps",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1530",
      "T1567"
    ],
    "playbook": true,
    "summary": "Bulk file downloads, anonymous links and external sharing by a user (OfficeActivity).",
    "steps": [
      {
        "ctx": "File downloads by the user per hour and IP",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where OfficeWorkload in (\"SharePoint\", \"OneDrive\")\n| where Operation in~ (\"FileDownloaded\", \"FileSyncDownloadedFull\", \"FileAccessed\")\n| where UserId =~ \"{{UPN}}\"\n| summarize Files = dcount(OfficeObjectId), Events = count() by bin(TimeGenerated, 1h), ClientIP, Operation\n| order by Files desc",
        "read": "Hundreds of files in one hour from an unfamiliar IP is exfiltration until proven otherwise; compare with the user's normal days."
      },
      {
        "ctx": "Anonymous links and external sharing",
        "kql": "OfficeActivity\n| where TimeGenerated > ago({{BASELINE}})\n| where Operation in~ (\"AnonymousLinkCreated\", \"SharingInvitationCreated\", \"AddedToSecureLink\", \"SecureLinkCreated\", \"SharingSet\")\n| project TimeGenerated, UserId, Operation, ClientIP, OfficeObjectId, TargetUserOrGroupName\n| order by TimeGenerated desc",
        "read": "Anonymous links on sensitive folders, or sharing to personal email domains, need the data owner to confirm."
      }
    ],
    "fp": "OneDrive sync clients on new laptops download everything; project teams sharing with partners."
  },
  {
    "id": "sentinel-firewall-hunting",
    "name": "Sentinel: firewall hunting (CommonSecurityLog)",
    "cat": "Firewall",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1071",
      "T1048",
      "T1046"
    ],
    "playbook": true,
    "summary": "Denied traffic, unusual outbound ports, top talkers by bytes and IoC IP lists in firewall / proxy logs.",
    "steps": [
      {
        "ctx": "IoC list: traffic to or from any of the IPs",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{BASELINE}})\n| where SourceIP in ({{IPS}}) or DestinationIP in ({{IPS}})\n| summarize Events = count(), Actions = make_set(DeviceAction), Ports = make_set(DestinationPort, 20), First = min(TimeGenerated), Last = max(TimeGenerated) by SourceIP, DestinationIP, DeviceVendor\n| order by Events desc",
        "read": "Put the IoC IPs comma-separated in IP addresses. Allowed outbound traffic to an IoC needs the internal source host investigated."
      },
      {
        "ctx": "Allowed outbound traffic on unusual ports",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where CommunicationDirection =~ \"Outbound\" or ipv4_is_private(SourceIP)\n| where DeviceAction !in~ (\"deny\", \"drop\", \"block\", \"reset-both\")\n| where DestinationPort !in (80, 443, 53, 123)\n| where not(ipv4_is_private(DestinationIP))\n| summarize Events = count(), Sources = dcount(SourceIP), SentBytes = sum(SentBytes) by DestinationPort, DestinationIP\n| order by Events desc",
        "read": "Ports like 4444, 1337, 8443 to a VPS, or SSH/RDP out to the internet, are worth checking in OSINT."
      },
      {
        "ctx": "Top internal senders by bytes to the internet (exfil check)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where ipv4_is_private(SourceIP) and not(ipv4_is_private(DestinationIP))\n| summarize SentMB = round(sum(SentBytes) / 1048576.0, 1), Destinations = dcount(DestinationIP) by SourceIP\n| top 20 by SentMB desc",
        "read": "Compare against backup and update servers. A workstation sending GBs to a single unknown destination needs escalation."
      },
      {
        "ctx": "Denied inbound traffic by source country (DeviceVendor geo fields vary)",
        "kql": "CommonSecurityLog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where DeviceAction in~ (\"deny\", \"drop\", \"block\")\n| where not(ipv4_is_private(SourceIP))\n| summarize Denied = count(), Ports = make_set(DestinationPort, 20) by SourceIP\n| top 50 by Denied desc",
        "read": "Internet scanning is constant; look for the same source later appearing as allowed."
      }
    ],
    "fp": "Backups, cloud sync and software updates create large or unusual flows."
  },
  {
    "id": "sentinel-linux-syslog",
    "name": "Sentinel: Linux SSH brute force, sudo and new users (Syslog)",
    "cat": "Linux",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1110",
      "T1548.003",
      "T1136.001"
    ],
    "playbook": true,
    "summary": "Linux auth logs in Syslog: failed SSH logins by source, successful logins after failures, sudo use and user creation.",
    "steps": [
      {
        "ctx": "Failed SSH logins by source IP",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Facility in (\"auth\", \"authpriv\") and SyslogMessage has_any (\"Failed password\", \"Invalid user\")\n| extend SourceIP = extract(@\"from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\", 1, SyslogMessage), User = extract(@\"(?:for|user) (?:invalid user )?(\\S+) from\", 1, SyslogMessage)\n| summarize Failures = count(), Users = make_set(User, 20), Hosts = make_set(Computer, 10) by SourceIP\n| order by Failures desc",
        "read": "Internet-facing SSH sees constant guessing. What matters is whether the same IP later appears in an 'Accepted' line (next step)."
      },
      {
        "ctx": "Successful SSH logins (Accepted password / publickey)",
        "kql": "Syslog\n| where TimeGenerated > ago({{LOOKBACK}})\n| where SyslogMessage has \"Accepted\"\n| extend SourceIP = extract(@\"from (\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})\", 1, SyslogMessage), User = extract(@\"for (\\S+) from\", 1, SyslogMessage), Method = extract(@\"Accepted (\\S+)\", 1, SyslogMessage)\n| project TimeGenerated, Computer, User, SourceIP, Method\n| order by TimeGenerated desc",
        "read": "An Accepted password from an IP that had many failures is a successful brute force."
      },
      {
        "ctx": "sudo commands and new users",
        "kql": "Syslog\n| where TimeGenerated > ago({{BASELINE}})\n| where (ProcessName == \"sudo\" and SyslogMessage has \"COMMAND=\") or SyslogMessage has_any (\"new user:\", \"useradd\", \"password changed\")\n| project TimeGenerated, Computer, ProcessName, SyslogMessage\n| order by TimeGenerated desc",
        "read": "sudo to bash/sh or edits to /etc/passwd, /etc/shadow, authorized_keys are the ones to read."
      }
    ],
    "fp": "Internet SSH scanners (noise unless a login succeeds); admins using sudo."
  },
  {
    "id": "sentinel-azure-activity",
    "name": "Sentinel: Azure subscription changes (role assignments, deletes, keys)",
    "cat": "Cloud infra",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1098",
      "T1485",
      "T1552.005"
    ],
    "playbook": true,
    "summary": "AzureActivity: who granted roles, deleted resources, listed storage keys or created VMs.",
    "steps": [
      {
        "ctx": "Role assignments created",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{BASELINE}})\n| where OperationNameValue =~ \"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE\" and ActivityStatusValue =~ \"Success\"\n| project TimeGenerated, Caller, CallerIpAddress, ResourceGroup, _ResourceId, Properties\n| order by TimeGenerated desc",
        "read": "Owner / Contributor / User Access Administrator granted by an unexpected caller or from an unknown IP is high priority."
      },
      {
        "ctx": "Resources deleted and storage keys listed",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where OperationNameValue endswith \"/DELETE\" or OperationNameValue =~ \"MICROSOFT.STORAGE/STORAGEACCOUNTS/LISTKEYS/ACTION\"\n| where ActivityStatusValue =~ \"Success\"\n| summarize Operations = count(), Resources = make_set(_ResourceId, 20) by Caller, CallerIpAddress, OperationNameValue\n| order by Operations desc",
        "read": "Mass deletes are destructive attacks; ListKeys gives full access to storage data."
      },
      {
        "ctx": "All operations by a caller",
        "kql": "AzureActivity\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Caller =~ \"{{UPN}}\" or CallerIpAddress == \"{{IP}}\"\n| summarize Operations = count(), First = min(TimeGenerated), Last = max(TimeGenerated) by Caller, CallerIpAddress, OperationNameValue, ActivityStatusValue\n| order by Last desc",
        "read": "Fill User (UPN) or IP. Service principals appear as an object ID in Caller."
      }
    ],
    "fp": "Infrastructure-as-code pipelines (Terraform, DevOps service principals)."
  },
  {
    "id": "sentinel-aws-cloudtrail",
    "name": "Sentinel: AWS CloudTrail (console logins, IAM changes, root use)",
    "cat": "Cloud infra",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1078.004",
      "T1098.001",
      "T1562.008"
    ],
    "playbook": true,
    "summary": "AWSCloudTrail: console logins without MFA, root account use, new access keys and logging being disabled.",
    "steps": [
      {
        "ctx": "Console logins (MFA, result, source)",
        "kql": "AWSCloudTrail\n| where TimeGenerated > ago({{LOOKBACK}})\n| where EventName == \"ConsoleLogin\"\n| extend MFA = tostring(parse_json(AdditionalEventData).MFAUsed), Result = tostring(parse_json(ResponseElements).ConsoleLogin)\n| project TimeGenerated, UserIdentityType, UserIdentityArn, SourceIpAddress, MFA, Result, UserAgent\n| order by TimeGenerated desc",
        "read": "Root logins and successful logins with MFA = No are the first to confirm."
      },
      {
        "ctx": "IAM changes: access keys, users, policies",
        "kql": "AWSCloudTrail\n| where TimeGenerated > ago({{BASELINE}})\n| where EventName in (\"CreateAccessKey\", \"CreateUser\", \"AttachUserPolicy\", \"PutUserPolicy\", \"CreateLoginProfile\", \"UpdateAssumeRolePolicy\", \"AddUserToGroup\")\n| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, RequestParameters, ErrorCode\n| order by TimeGenerated desc",
        "read": "New access keys or AdministratorAccess attached from an unknown IP is a takeover pattern."
      },
      {
        "ctx": "Logging and guardrails disabled",
        "kql": "AWSCloudTrail\n| where TimeGenerated > ago({{BASELINE}})\n| where EventName in (\"StopLogging\", \"DeleteTrail\", \"UpdateTrail\", \"DeleteDetector\", \"DisableSecurityHub\", \"PutBucketPublicAccessBlock\", \"DeleteFlowLogs\")\n| project TimeGenerated, EventName, UserIdentityArn, SourceIpAddress, RequestParameters",
        "read": "Any successful row outside a change window is high priority."
      }
    ],
    "fp": "Automation roles and approved admin changes."
  },
  {
    "id": "sentinel-waf",
    "name": "Sentinel: Web Application Firewall / Application Gateway hits",
    "cat": "Web & proxy",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1190",
      "T1595.002"
    ],
    "playbook": true,
    "summary": "Azure Application Gateway / Front Door WAF: matched and blocked rules by client IP and URL.",
    "steps": [
      {
        "ctx": "WAF matches by client IP and rule (resource-specific table)",
        "kql": "AGWFirewallLogs\n| where TimeGenerated > ago({{LOOKBACK}})\n| summarize Hits = count(), Actions = make_set(Action), URIs = make_set(RequestUri, 20) by ClientIp, RuleId, Message\n| order by Hits desc",
        "read": "Blocked = WAF stopped it. Matched/Detected in detection mode means it reached the app; check the response in AGWAccessLogs."
      },
      {
        "ctx": "Requests from the IP (AzureDiagnostics, legacy mode)",
        "kql": "AzureDiagnostics\n| where TimeGenerated > ago({{LOOKBACK}})\n| where Category in (\"ApplicationGatewayFirewallLog\", \"ApplicationGatewayAccessLog\", \"FrontDoorWebApplicationFirewallLog\")\n| where clientIp_s == \"{{IP}}\" or clientIP_s == \"{{IP}}\"\n| project TimeGenerated, Category, clientIp_s, clientIP_s, requestUri_s, ruleId_s, action_s, httpStatus_d, Message\n| order by TimeGenerated desc",
        "read": "httpStatus 200 on exploit-looking paths (../, /etc/passwd, ${jndi:, UNION SELECT) needs the app owner involved."
      }
    ],
    "fp": "Vulnerability scanners run by the client; false positives on legitimate POST bodies."
  },
  {
    "id": "sentinel-threat-intel",
    "name": "Sentinel: threat intelligence matches (ThreatIntelIndicators)",
    "cat": "Threat intel",
    "platform": "Sentinel",
    "src": "Microsoft Sentinel (Log Analytics)",
    "sev": "medium",
    "mitre": [
      "T1071"
    ],
    "playbook": true,
    "summary": "Look up an IoC in the workspace TI feed and match active TI IPs against sign-ins and firewall logs.",
    "steps": [
      {
        "ctx": "Is the IoC in the TI feed?",
        "kql": "ThreatIntelIndicators\n| where TimeGenerated > ago({{BASELINE}})\n| where ObservableValue has \"{{IP}}\" or ObservableValue has \"{{DOMAIN}}\"\n| summarize arg_max(TimeGenerated, *) by Id\n| project TimeGenerated, ObservableKey, ObservableValue, Confidence, IsActive, ValidUntil, SourceSystem, Tags\n| order by TimeGenerated desc",
        "read": "Older workspaces use ThreatIntelligenceIndicator (NetworkIP, DomainName, Active columns). IsActive false or an old ValidUntil means the indicator expired."
      },
      {
        "ctx": "Active TI IPs seen in sign-ins and firewall logs",
        "kql": "let TI = ThreatIntelIndicators\n    | where TimeGenerated > ago(30d) and IsActive == true and ObservableKey has \"ipv4\"\n    | summarize arg_max(TimeGenerated, *) by ObservableValue\n    | project TIIP = ObservableValue, Confidence, SourceSystem;\nunion isfuzzy=true\n    (SigninLogs | where TimeGenerated > ago({{LOOKBACK}}) | project TimeGenerated, Source = \"SigninLogs\", IP = IPAddress, Who = UserPrincipalName, Result = ResultType),\n    (CommonSecurityLog | where TimeGenerated > ago({{LOOKBACK}}) | project TimeGenerated, Source = \"Firewall\", IP = DestinationIP, Who = SourceIP, Result = DeviceAction)\n| join kind=inner TI on $left.IP == $right.TIIP\n| summarize Hits = count(), Last = max(TimeGenerated) by Source, IP, Who, Result, Confidence, SourceSystem\n| order by Hits desc",
        "read": "Successful sign-ins (Result 0) or allowed firewall traffic to a TI IP are the cases to escalate."
      }
    ],
    "fp": "Low-confidence or expired indicators; shared cloud IPs."
  },
  {
    "id": "cs-host-activity",
    "name": "CrowdStrike: host activity (processes, network, DNS, files)",
    "cat": "Endpoint",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "info",
    "mitre": [
      "T1059",
      "T1071"
    ],
    "playbook": true,
    "summary": "Everything Falcon recorded on one host: process starts, outbound connections, DNS lookups and new executables. Start here for any endpoint detection.",
    "steps": [
      {
        "ctx": "Processes started on the host (command line, parent, user, hash)",
        "kql": "#event_simpleName=ProcessRollup2 ComputerName=\"{{DEVICE}}\"\n| table([@timestamp, UserName, FileName, CommandLine, ParentBaseFileName, SHA256HashData], limit=500)\n| sort(@timestamp, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Fields like ComputerName take one value. Script hosts (powershell, cmd, wscript, mshta, rundll32) with encoded or download command lines need a closer look."
      },
      {
        "ctx": "Outbound network connections from the host",
        "kql": "#event_simpleName=NetworkConnectIP4 ComputerName=\"{{DEVICE}}\"\n| groupBy([RemoteAddressIP4, RemotePort], function=[count(), min(@timestamp, as=First), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "Rare external IPs and unusual ports (4444, 8080 to a VPS, etc.) are the ones to check in OSINT."
      },
      {
        "ctx": "DNS lookups from the host",
        "kql": "#event_simpleName=DnsRequest ComputerName=\"{{DEVICE}}\"\n| groupBy([DomainName], function=[count(), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "Newly registered or random-looking domains, and very long subdomains (DNS tunnelling), stand out."
      },
      {
        "ctx": "New executables written to disk",
        "kql": "#event_simpleName=NewExecutableWritten ComputerName=\"{{DEVICE}}\"\n| table([@timestamp, TargetFileName, ContextBaseFileName, SHA256HashData])\n| sort(@timestamp, order=desc)",
        "read": "Executables dropped into Temp, ProgramData, Public or AppData by a browser, Office or script host are suspicious."
      },
      {
        "ctx": "User logons on the host (success and failure)",
        "kql": "#event_simpleName=/^UserLogon/ ComputerName=\"{{DEVICE}}\"\n| groupBy([#event_simpleName, UserName, LogonType], function=[count(), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "UserLogonFailed2 bursts followed by UserLogon for the same account is a brute-force success. LogonType 10 is RDP."
      }
    ],
    "fp": "Software updaters and IT management agents start many processes and connections; compare with other hosts in the same role.",
    "platform": "CrowdStrike"
  },
  {
    "id": "cs-ioc-hunt",
    "name": "CrowdStrike: hunt an IoC across all hosts (hash, IP, domain)",
    "cat": "Endpoint",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Find every host that ran a file, talked to an IP, or looked up a domain from an alert or threat-intel report.",
    "steps": [
      {
        "ctx": "Which hosts ran this file (SHA-256)?",
        "kql": "#event_simpleName=ProcessRollup2 SHA256HashData=\"{{SHA256}}\"\n| groupBy([ComputerName, UserName, FileName], function=[count(), min(@timestamp, as=First), max(@timestamp, as=Last)])",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Fields like ComputerName take one value."
      },
      {
        "ctx": "Which hosts connected to this IP?",
        "kql": "#event_simpleName=NetworkConnectIP4 RemoteAddressIP4=\"{{IP}}\"\n| groupBy([ComputerName, RemotePort], function=[count(), min(@timestamp, as=First), max(@timestamp, as=Last)])",
        "read": "Several hosts talking to the same external IP widens the incident."
      },
      {
        "ctx": "Which hosts looked up this domain?",
        "kql": "#event_simpleName=DnsRequest DomainName=*{{DOMAIN}}*\n| groupBy([ComputerName, DomainName], function=[count(), min(@timestamp, as=First), max(@timestamp, as=Last)])",
        "read": "Matches the domain and its subdomains. Put the domain in Domain / URL fragment."
      }
    ],
    "fp": "Shared infrastructure (CDNs, cloud providers) appears on many hosts; check the IP owner in OSINT first.",
    "platform": "CrowdStrike"
  },
  {
    "id": "cs-detections",
    "name": "CrowdStrike: detections and alerts overview",
    "cat": "SIEM health",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Which detections fired, on which hosts, and how often, to triage the queue and spot repeat offenders.",
    "steps": [
      {
        "ctx": "Detections by name and severity",
        "kql": "#event_simpleName=DetectionSummaryEvent OR #event_simpleName=EppDetectionSummaryEvent\n| groupBy([DetectName, Severity], function=[count(), count(ComputerName, distinct=true, as=Hosts), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Fields like ComputerName take one value. Event names vary by Falcon version; if nothing returns, search #event_simpleName=*Detection* to find yours."
      },
      {
        "ctx": "Detections on one host",
        "kql": "(#event_simpleName=DetectionSummaryEvent OR #event_simpleName=EppDetectionSummaryEvent) ComputerName=\"{{DEVICE}}\"\n| table([@timestamp, DetectName, Severity, FileName, CommandLine, UserName])\n| sort(@timestamp, order=desc)",
        "read": "Several different detections on one host in a short time usually means a real intrusion rather than one noisy rule."
      }
    ],
    "fp": "Reference entry, not an alert.",
    "platform": "CrowdStrike"
  },
  {
    "id": "cs-suspicious-process",
    "name": "CrowdStrike: Office spawning scripts, encoded PowerShell and LOLBins",
    "cat": "Endpoint",
    "platform": "CrowdStrike",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "medium",
    "mitre": [
      "T1059.001",
      "T1204.002",
      "T1218"
    ],
    "playbook": true,
    "summary": "Common initial-access and execution patterns in ProcessRollup2: Office apps launching script engines, encoded PowerShell, and living-off-the-land binaries.",
    "steps": [
      {
        "ctx": "Office applications spawning script engines",
        "kql": "#event_simpleName=ProcessRollup2\n| ParentBaseFileName=/^(winword|excel|outlook|powerpnt|onenote)\\.exe$/i\n| FileName=/^(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$/i\n| table([@timestamp, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])\n| sort(@timestamp, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Any result is high priority: it is the classic malicious-document pattern. Check the document's origin (email, download)."
      },
      {
        "ctx": "Encoded PowerShell, with the payload extracted",
        "kql": "#event_simpleName=ProcessRollup2 FileName=/^(powershell|pwsh)\\.exe$/i\n| CommandLine=/\\s-(e|en|enc|enco|encodedcommand)\\s/i\n| regex(\"(?i)-(?:e|en|enc|encodedcommand)\\s+(?<EncodedPayload>[A-Za-z0-9+/=]{20,})\", field=CommandLine, strict=false)\n| table([@timestamp, ComputerName, UserName, ParentBaseFileName, EncodedPayload, CommandLine])\n| sort(@timestamp, order=desc)",
        "read": "Decode EncodedPayload as Base64 UTF-16LE (CyberChef: From Base64 -> Decode text UTF-16LE)."
      },
      {
        "ctx": "LOLBins with URLs or download flags",
        "kql": "#event_simpleName=ProcessRollup2\n| FileName=/^(certutil|bitsadmin|mshta|rundll32|regsvr32|curl|wget)\\.exe$/i\n| CommandLine=/(http|https|ftp):\\/\\/|urlcache|-split|\\/transfer|scrobj/i\n| groupBy([ComputerName, UserName, FileName, CommandLine], function=[count(), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "certutil -urlcache, bitsadmin /transfer and regsvr32 /i:http (Squiblydoo) are download-and-execute tricks."
      }
    ],
    "fp": "Office add-ins and macros used by finance teams; IT scripts using certutil or curl."
  },
  {
    "id": "cs-persistence",
    "name": "CrowdStrike: persistence (services, scheduled tasks, Run keys)",
    "cat": "Endpoint",
    "platform": "CrowdStrike",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "medium",
    "mitre": [
      "T1543.003",
      "T1053.005",
      "T1547.001"
    ],
    "playbook": true,
    "summary": "New services, scheduled tasks and registry autoruns created on a host.",
    "steps": [
      {
        "ctx": "Scheduled tasks and services created on the host",
        "kql": "#event_simpleName=/^(ScheduledTaskRegistered|ServiceStarted|ModifyServiceBinary)$/ ComputerName=\"{{DEVICE}}\"\n| table([@timestamp, #event_simpleName, TaskName, TaskExecCommand, ServiceDisplayName, ImageFileName, UserName])\n| sort(@timestamp, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Tasks or services running from AppData, Temp, ProgramData or Public, or launching powershell/cmd, are suspicious."
      },
      {
        "ctx": "Run / RunOnce registry autoruns",
        "kql": "#event_simpleName=/^(AsepValueUpdate|RegGenericValueUpdate)$/ ComputerName=\"{{DEVICE}}\"\n| RegObjectName=/\\\\CurrentVersion\\\\(Run|RunOnce)/i\n| table([@timestamp, RegObjectName, RegValueName, RegStringValue, UserName])\n| sort(@timestamp, order=desc)",
        "read": "Values pointing to scripts or binaries in user-writable folders are the common malware persistence."
      }
    ],
    "fp": "Software updaters (Google, Adobe, Teams) create tasks and Run keys."
  },
  {
    "id": "cs-identity-logons",
    "name": "CrowdStrike: brute force and NTLM lateral movement",
    "cat": "Identity",
    "platform": "CrowdStrike",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "medium",
    "mitre": [
      "T1110",
      "T1021.002",
      "T1550.002"
    ],
    "playbook": true,
    "summary": "Failed logons per account and source, and one account using NTLM network logons across many hosts.",
    "steps": [
      {
        "ctx": "Failed logons by account and source",
        "kql": "#event_simpleName=UserLogonFailed2\n| groupBy([UserName, RemoteAddressIP4], function=[count(as=Failures), count(field=ComputerName, distinct=true, as=Hosts), max(@timestamp, as=Last)])\n| Failures > 10\n| sort(Failures, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Many failures from one source against one user is brute force; one source against many users is spraying. Check for a later UserLogon for the same pair."
      },
      {
        "ctx": "Logons for one user across hosts",
        "kql": "#event_simpleName=UserLogon UserName=\"{{ACCOUNT}}\"\n| groupBy([ComputerName, LogonType, RemoteAddressIP4], function=[count(), min(@timestamp, as=First), max(@timestamp, as=Last)])\n| sort(Last, order=desc)",
        "read": "LogonType 10 = RDP, 3 = network, 2 = console. New hosts for this user around the alert time show lateral movement."
      },
      {
        "ctx": "NTLM network logons from one source to 3+ hosts",
        "kql": "#event_simpleName=UserLogon LogonType=3 AuthenticationPackage=\"NTLM\"\n| UserName!=/\\$$/\n| groupBy([UserName, RemoteAddressIP4], function=[count(field=ComputerName, distinct=true, as=TargetHosts), collect([ComputerName])])\n| TargetHosts >= 3\n| sort(TargetHosts, order=desc)",
        "read": "Pass-the-hash and PsExec sweeps look like this. Exclude known admin jump hosts and vulnerability scanners."
      }
    ],
    "fp": "Scanners, monitoring tools and admin jump boxes authenticate to many hosts."
  },
  {
    "id": "cs-network-dns",
    "name": "CrowdStrike: DNS tunnelling and outbound RDP/SMB/SSH",
    "cat": "DNS",
    "platform": "CrowdStrike",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "medium",
    "mitre": [
      "T1071.004",
      "T1048",
      "T1021"
    ],
    "playbook": true,
    "summary": "High DNS query volume per domain, long subdomains, and remote-access protocols going out to the internet.",
    "steps": [
      {
        "ctx": "High DNS query volume per domain",
        "kql": "#event_simpleName=DnsRequest\n| groupBy([DomainName], function=[count(as=QueryCount), count(field=ComputerName, distinct=true, as=Hosts)])\n| QueryCount > 100\n| sort(QueryCount, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Mostly CDNs and Microsoft. A rare domain queried thousands of times by one host, with random subdomains, suggests DNS tunnelling or beaconing."
      },
      {
        "ctx": "Very long DNS names (tunnelling)",
        "kql": "#event_simpleName=DnsRequest\n| len := length(DomainName)\n| len > 60\n| groupBy([ComputerName, DomainName], function=count())\n| sort(_count, order=desc)",
        "read": "Long hex/base32-looking labels under one parent domain are data being encoded into DNS."
      },
      {
        "ctx": "Outbound RDP, SMB, SSH or WinRM to public IPs",
        "kql": "#event_simpleName=NetworkConnectIP4 RemotePort=/^(22|445|3389|5985|5986)$/\n| !cidr(RemoteAddressIP4, subnet=[\"10.0.0.0/8\", \"172.16.0.0/12\", \"192.168.0.0/16\", \"127.0.0.0/8\"])\n| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[count(), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "Workstations should rarely open these protocols to the internet; check the destination in OSINT."
      }
    ],
    "fp": "Security tools and CDNs generate heavy DNS; admins using SSH to cloud servers."
  },
  {
    "id": "cs-sensor-health",
    "name": "CrowdStrike: sensors reporting and event volume",
    "cat": "SIEM health",
    "platform": "CrowdStrike",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Which hosts stopped sending data and which event types are in the data.",
    "steps": [
      {
        "ctx": "Last time each host sent data",
        "kql": "#event_simpleName=SensorHeartbeat\n| groupBy([ComputerName], function=max(@timestamp, as=LastSeen))\n| sort(LastSeen, order=asc)\n| LastSeenReadable := formatTime(\"%Y-%m-%d %H:%M\", field=LastSeen)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). Hosts at the top have been quiet the longest: offline, uninstalled sensor, or tampering. Set a time range of at least 7 days."
      },
      {
        "ctx": "Event types in the data",
        "kql": "groupBy([#event_simpleName], function=count())\n| sort(_count, order=desc)\n| head(50)",
        "read": "Use it to learn which event names exist in this tenant before writing a hunt."
      }
    ],
    "fp": "Laptops off the network and decommissioned hosts."
  },
  {
    "id": "cs-linux",
    "name": "CrowdStrike: Linux reverse shells, droppers and persistence",
    "cat": "Linux",
    "platform": "CrowdStrike",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "medium",
    "mitre": [
      "T1059.004",
      "T1105",
      "T1053.003"
    ],
    "playbook": true,
    "summary": "Linux sensor process events: curl/wget piped to shell, /dev/tcp reverse shells, cron and authorized_keys changes.",
    "steps": [
      {
        "ctx": "Reverse shells and download-and-execute",
        "kql": "#event_simpleName=ProcessRollup2 event_platform=Lin\n| CommandLine=/(\\/dev\\/tcp\\/|nc\\s+-e|ncat\\s|bash\\s+-i|mkfifo|curl[^|]*\\|\\s*(ba)?sh|wget[^|]*\\|\\s*(ba)?sh|base64\\s+-d)/i\n| table([@timestamp, ComputerName, UserName, ParentBaseFileName, CommandLine])\n| sort(@timestamp, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). A web server user (www-data, nginx, apache, tomcat) running these means the application was exploited."
      },
      {
        "ctx": "Cron, sudoers and SSH key changes",
        "kql": "#event_simpleName=ProcessRollup2 event_platform=Lin\n| CommandLine=/(crontab|\\/etc\\/cron|\\/etc\\/sudoers|authorized_keys|useradd|usermod)/i\n| table([@timestamp, ComputerName, UserName, CommandLine])\n| sort(@timestamp, order=desc)",
        "read": "Persistence on Linux. Confirm with the server owner."
      }
    ],
    "fp": "Configuration management and admin maintenance."
  },
  {
    "id": "cs-threat-intel",
    "name": "CrowdStrike: match connections and DNS against Falcon threat intel",
    "cat": "Threat intel",
    "platform": "CrowdStrike",
    "src": "CrowdStrike Falcon (LogScale CQL)",
    "sev": "medium",
    "mitre": [
      "T1071"
    ],
    "playbook": true,
    "summary": "Use the NG-SIEM ioc:lookup() function to flag IPs and domains that CrowdStrike intelligence knows about.",
    "steps": [
      {
        "ctx": "Outbound connections to known-bad IPs",
        "kql": "#event_simpleName=NetworkConnectIP4\n| ioc:lookup(field=[RemoteAddressIP4], type=\"ip_address\", confidenceThreshold=\"high\")\n| groupBy([ComputerName, RemoteAddressIP4, ioc[0].labels], function=[count(), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "CrowdStrike Falcon LogScale / Next-Gen SIEM query (CQL), not KQL. Set the time range in the Falcon search bar (the Look-back field isn't used). ioc:lookup needs Falcon Intelligence / Next-Gen SIEM. Rows mean a host talked to an IP CrowdStrike rates high confidence."
      },
      {
        "ctx": "DNS lookups of known-bad domains",
        "kql": "#event_simpleName=DnsRequest\n| ioc:lookup(field=[DomainName], type=\"domain\", confidenceThreshold=\"high\")\n| groupBy([ComputerName, DomainName], function=[count(), max(@timestamp, as=Last)])\n| sort(_count, order=desc)",
        "read": "Follow up with the process that made the lookup (ContextProcessId) in host activity."
      }
    ],
    "fp": "Sinkholed or expired indicators."
  },
  {
    "id": "splunk-data-overview",
    "name": "Splunk: what data is in this Splunk? (indexes, sourcetypes, hosts)",
    "cat": "SIEM health",
    "src": "Splunk (SPL)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Start here on a new Splunk: which indexes and sourcetypes have data, how much, and which hosts stopped sending.",
    "steps": [
      {
        "ctx": "Event counts by index and sourcetype (fast, using tstats)",
        "kql": "| tstats count where index=* earliest=-{{LOOKBACK}} by index, sourcetype\n| sort - count",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Fields like host take one value. Use these index and sourcetype names in the other Splunk entries."
      },
      {
        "ctx": "Hosts that stopped sending data",
        "kql": "| tstats latest(_time) as last_seen where index=* earliest=-{{BASELINE}} by host, index\n| eval hours_silent=round((now()-last_seen)/3600,1)\n| where hours_silent > 2\n| convert ctime(last_seen)\n| sort - hours_silent",
        "read": "A host that went quiet may be off, isolated, or have its forwarder stopped by an attacker."
      }
    ],
    "fp": "Reference entry, not an alert.",
    "platform": "Splunk"
  },
  {
    "id": "splunk-windows-auth",
    "name": "Splunk: Windows logons (failed and successful)",
    "cat": "Identity",
    "src": "Splunk (SPL) – WinEventLog:Security",
    "sev": "info",
    "mitre": [
      "T1110",
      "T1078"
    ],
    "playbook": true,
    "summary": "Brute force and suspicious logons from Windows Security events (4624 / 4625).",
    "steps": [
      {
        "ctx": "Failed logons by account and source (brute force?)",
        "kql": "index=* sourcetype=\"WinEventLog:Security\" EventCode=4625 earliest=-{{LOOKBACK}}\n| stats count as failures, dc(Workstation_Name) as workstations, values(Source_Network_Address) as sources by Account_Name, host\n| where failures > 10\n| sort - failures",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Fields like host take one value. Many failures from one source against many accounts is password spraying; against one account, brute force."
      },
      {
        "ctx": "Successful logons for one account",
        "kql": "index=* sourcetype=\"WinEventLog:Security\" EventCode=4624 Account_Name=\"{{ACCOUNT}}\" earliest=-{{LOOKBACK}}\n| stats count, values(Logon_Type) as logon_types, values(Source_Network_Address) as sources, latest(_time) as last by host\n| convert ctime(last)\n| sort - count",
        "read": "Put the account in Account name. Logon type 10 is RDP, 3 network. A success from a source that also had many failures means the brute force worked."
      }
    ],
    "fp": "Service accounts with expired passwords produce constant 4625s; check the account owner.",
    "platform": "Splunk"
  },
  {
    "id": "splunk-process",
    "name": "Splunk: process creation (Sysmon 1 / Windows 4688)",
    "cat": "Endpoint",
    "src": "Splunk (SPL) – Sysmon / WinEventLog",
    "sev": "info",
    "mitre": [
      "T1059",
      "T1105"
    ],
    "playbook": true,
    "summary": "What ran on a host, with command lines and parents, plus a hunt for common living-off-the-land abuse.",
    "steps": [
      {
        "ctx": "Processes on one host (Sysmon EventCode 1)",
        "kql": "index=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 host=\"{{DEVICE}}\" earliest=-{{LOOKBACK}}\n| table _time, User, ParentImage, Image, CommandLine, Hashes\n| sort - _time",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Fields like host take one value. Without Sysmon, use sourcetype=\"WinEventLog:Security\" EventCode=4688 and the New_Process_Name / Process_Command_Line fields."
      },
      {
        "ctx": "Living-off-the-land binaries downloading or running code (all hosts)",
        "kql": "index=* (sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1) earliest=-{{LOOKBACK}}\n  (Image=\"*\\\\certutil.exe\" CommandLine=\"*urlcache*\") OR (Image=\"*\\\\powershell.exe\" (CommandLine=\"*-enc*\" OR CommandLine=\"*DownloadString*\" OR CommandLine=\"*IEX*\")) OR (Image=\"*\\\\mshta.exe\") OR (Image=\"*\\\\rundll32.exe\" CommandLine=\"*http*\")\n| stats count, values(CommandLine) as commands by host, User, Image\n| sort - count",
        "read": "Each row is a host and user that used a built-in Windows tool in a way attackers often do. Check the parent process and decode -enc strings."
      }
    ],
    "fp": "IT scripts and software installers use PowerShell and certutil legitimately; compare with known admin accounts.",
    "platform": "Splunk"
  },
  {
    "id": "splunk-network",
    "name": "Splunk: firewall / network traffic for an IP",
    "cat": "Firewall",
    "src": "Splunk (SPL) – CIM Network_Traffic",
    "sev": "info",
    "mitre": [
      "T1071",
      "T1041"
    ],
    "playbook": true,
    "summary": "Who talked to an IP, on which ports, and how much data moved, using the CIM Network_Traffic data model.",
    "steps": [
      {
        "ctx": "Sessions to or from the IP (CIM data model)",
        "kql": "| tstats count, sum(All_Traffic.bytes_out) as bytes_out, sum(All_Traffic.bytes_in) as bytes_in, values(All_Traffic.dest_port) as ports, values(All_Traffic.action) as actions\n  from datamodel=Network_Traffic where (All_Traffic.src_ip=\"{{IP}}\" OR All_Traffic.dest_ip=\"{{IP}}\") earliest=-{{LOOKBACK}}\n  by All_Traffic.src_ip, All_Traffic.dest_ip\n| sort - bytes_out",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Fields like host take one value. Needs the Network_Traffic data model (accelerated in Enterprise Security). Large bytes_out to one external IP is the exfiltration pattern."
      },
      {
        "ctx": "Raw firewall events for the IP (no data model)",
        "kql": "index=* (\"{{IP}}\") earliest=-{{LOOKBACK}} (sourcetype=*firewall* OR sourcetype=pan:traffic OR sourcetype=fortigate_traffic OR sourcetype=cisco:asa)\n| stats count, values(action) as actions, values(dest_port) as ports by src_ip, dest_ip, sourcetype\n| sort - count",
        "read": "Use when the data model isn't set up. Adjust the sourcetypes to your firewall."
      }
    ],
    "fp": "Reference entry; CDN and cloud IPs show up everywhere, so check the owner in OSINT first.",
    "platform": "Splunk"
  },
  {
    "id": "splunk-linux-ssh",
    "name": "Splunk: Linux SSH logons (brute force and success)",
    "cat": "Linux",
    "src": "Splunk (SPL) – linux_secure",
    "sev": "info",
    "mitre": [
      "T1110",
      "T1021.004"
    ],
    "playbook": true,
    "summary": "SSH failures and successes from /var/log/secure or auth.log (sourcetype linux_secure).",
    "steps": [
      {
        "ctx": "Failed SSH logins by source IP and user",
        "kql": "index=* sourcetype=linux_secure \"Failed password\" earliest=-{{LOOKBACK}}\n| rex \"Failed password for (invalid user )?(?<user>\\S+) from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)\"\n| stats count as failures, dc(user) as users by src_ip, host\n| sort - failures",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Fields like host take one value."
      },
      {
        "ctx": "Successful SSH logins (did any attacker get in?)",
        "kql": "index=* sourcetype=linux_secure \"Accepted\" earliest=-{{LOOKBACK}}\n| rex \"Accepted (?<method>\\S+) for (?<user>\\S+) from (?<src_ip>\\d+\\.\\d+\\.\\d+\\.\\d+)\"\n| stats count, latest(_time) as last by host, user, src_ip, method\n| convert ctime(last)\n| sort - count",
        "read": "Any Accepted row from an IP that also had many failures means the brute force succeeded."
      }
    ],
    "fp": "Internet-facing SSH gets constant scanning; failures alone are usually noise.",
    "platform": "Splunk"
  },
  {
    "id": "splunk-suspicious-powershell",
    "name": "Splunk: suspicious PowerShell and discovery commands",
    "cat": "Endpoint",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1059.001",
      "T1027",
      "T1082"
    ],
    "playbook": true,
    "summary": "Encoded or download PowerShell and discovery commands from Windows 4688, Sysmon 1 and PowerShell 4104 script block logs.",
    "steps": [
      {
        "ctx": "Encoded or download PowerShell (4688 / Sysmon 1)",
        "kql": "index=* (EventCode=4688 OR (sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1)) earliest=-{{LOOKBACK}}\n| eval cmd=coalesce(CommandLine, Process_Command_Line)\n| search cmd=\"*powershell*\" (cmd=\"*-enc*\" OR cmd=\"*FromBase64String*\" OR cmd=\"*DownloadString*\" OR cmd=\"*IEX*\" OR cmd=\"*-w hidden*\")\n| table _time, host, user, ParentImage, cmd\n| sort - _time",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Field names differ between the Windows TA (Process_Command_Line) and Sysmon (CommandLine); coalesce covers both."
      },
      {
        "ctx": "PowerShell script block content (4104)",
        "kql": "index=* sourcetype=\"XmlWinEventLog:Microsoft-Windows-PowerShell/Operational\" EventCode=4104 earliest=-{{LOOKBACK}}\n| search ScriptBlockText=\"*Invoke-Mimikatz*\" OR ScriptBlockText=\"*Net.WebClient*\" OR ScriptBlockText=\"*AmsiUtils*\" OR ScriptBlockText=\"*FromBase64String*\"\n| table _time, host, UserID, ScriptBlockText\n| sort - _time",
        "read": "4104 shows the decoded script, so it catches what the command line hides. Needs script block logging enabled."
      },
      {
        "ctx": "Discovery commands on one host",
        "kql": "index=* (EventCode=4688 OR EventCode=1) host=\"{{DEVICE}}\" earliest=-{{LOOKBACK}}\n| eval cmd=coalesce(CommandLine, Process_Command_Line)\n| search cmd=\"*whoami*\" OR cmd=\"*net user*\" OR cmd=\"*net group*\" OR cmd=\"*nltest*\" OR cmd=\"*systeminfo*\" OR cmd=\"*ipconfig /all*\"\n| table _time, host, user, cmd\n| sort _time",
        "read": "Several discovery commands in a few minutes is hands-on-keyboard activity."
      }
    ],
    "fp": "Admin, SCCM and RMM scripts."
  },
  {
    "id": "splunk-account-changes",
    "name": "Splunk: account changes, lockouts and log clearing",
    "cat": "Identity",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1136",
      "T1098",
      "T1070.001"
    ],
    "playbook": true,
    "summary": "New accounts, privileged group additions, lockouts and Security log cleared on Windows.",
    "steps": [
      {
        "ctx": "Accounts created and added to groups",
        "kql": "index=* sourcetype=\"WinEventLog:Security\" EventCode IN (4720, 4728, 4732, 4756) earliest=-{{BASELINE}}\n| table _time, host, EventCode, name, src_user, user, Group_Name\n| sort - _time",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. src_user made the change; user is the account affected. Additions to Domain Admins / Administrators are high priority."
      },
      {
        "ctx": "Account lockouts and the caller computer",
        "kql": "index=* sourcetype=\"WinEventLog:Security\" EventCode=4740 earliest=-{{LOOKBACK}}\n| stats count, values(Caller_Computer_Name) as caller, latest(_time) as last by user\n| convert ctime(last)\n| sort - count",
        "read": "Caller_Computer_Name is where the bad passwords came from."
      },
      {
        "ctx": "Security log cleared (1102)",
        "kql": "index=* (sourcetype=\"WinEventLog:Security\" EventCode=1102) OR (sourcetype=\"WinEventLog:System\" EventCode=104) earliest=-{{BASELINE}}\n| table _time, host, EventCode, user, Message",
        "read": "Log clearing outside maintenance is a strong sign of an intruder covering tracks."
      }
    ],
    "fp": "Helpdesk onboarding and IAM tools."
  },
  {
    "id": "splunk-azure-signins",
    "name": "Splunk: Entra ID / Microsoft 365 sign-ins for a user",
    "cat": "Identity",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1078.004"
    ],
    "playbook": true,
    "summary": "Sign-ins from the Microsoft Azure / O365 add-ons: by user, by country, and failures by IP.",
    "steps": [
      {
        "ctx": "Sign-ins for the user (Entra ID)",
        "kql": "index=* sourcetype=\"azure:aad:signin\" userPrincipalName=\"{{UPN}}\" earliest=-{{LOOKBACK}}\n| table _time, userPrincipalName, ipAddress, location.countryOrRegion, location.city, appDisplayName, clientAppUsed, status.errorCode, status.failureReason\n| sort - _time",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. status.errorCode 0 = success. Sourcetypes vary: try sourcetype=\"o365:management:activity\" Operation=UserLoggedIn if this returns nothing."
      },
      {
        "ctx": "Successful sign-ins outside a country",
        "kql": "index=* sourcetype=\"azure:aad:signin\" userPrincipalName=\"{{UPN}}\" status.errorCode=0 earliest=-{{BASELINE}}\n| rename location.countryOrRegion as country\n| search NOT country IN ({{COUNTRIES}})\n| stats count, values(ipAddress) as ips, min(_time) as first, max(_time) as last by country\n| convert ctime(first) ctime(last)",
        "read": "Put the home country codes in Countries (e.g. AU)."
      },
      {
        "ctx": "Failed sign-ins by source IP (spraying)",
        "kql": "index=* sourcetype=\"azure:aad:signin\" status.errorCode!=0 earliest=-{{LOOKBACK}}\n| stats count as failures, dc(userPrincipalName) as users, values(status.failureReason) as reasons by ipAddress\n| where users > 5\n| sort - failures",
        "read": "One IP failing against many users is password spraying; check for any success from the same IP."
      }
    ],
    "fp": "Travel and VPN egress; Microsoft service IPs."
  },
  {
    "id": "splunk-o365-email",
    "name": "Splunk: Microsoft 365 inbox rules and message trace",
    "cat": "Email",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1114.003",
      "T1566"
    ],
    "playbook": true,
    "summary": "Inbox rules and forwarding from the O365 management activity feed, and who received mail from a sender.",
    "steps": [
      {
        "ctx": "Inbox rules and forwarding changes for the user",
        "kql": "index=* sourcetype=\"o365:management:activity\" Workload=Exchange Operation IN (\"New-InboxRule\", \"Set-InboxRule\", \"UpdateInboxRules\", \"Set-Mailbox\") UserId=\"{{UPN}}\" earliest=-{{BASELINE}}\n| table _time, UserId, Operation, ClientIP, Parameters{}.Name, Parameters{}.Value\n| sort - _time",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Look for ForwardTo, RedirectTo, ForwardingSmtpAddress, DeleteMessage or MoveToFolder."
      },
      {
        "ctx": "Who received mail from the sender (message trace)",
        "kql": "index=* sourcetype=\"o365:reporting:messagetrace\" SenderAddress=\"{{SENDER}}\" earliest=-{{BASELINE}}\n| stats count, values(Subject) as subjects, values(Status) as status by RecipientAddress\n| sort - count",
        "read": "Needs the Microsoft 365 add-on message trace input. Status Delivered means it reached the mailbox."
      }
    ],
    "fp": "Users' own rules; newsletters."
  },
  {
    "id": "splunk-dns-web",
    "name": "Splunk: DNS, web proxy and threat-intel matches",
    "cat": "Web & proxy",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1071",
      "T1595"
    ],
    "playbook": true,
    "summary": "Top DNS queries, scanner user agents, rare outbound destinations, and firewall hits against a threat-intel index.",
    "steps": [
      {
        "ctx": "Hosts that looked up the domain",
        "kql": "index=* (sourcetype=*dns* OR sourcetype=\"stream:dns\") query=\"*{{DOMAIN}}*\" earliest=-{{BASELINE}}\n| stats count, min(_time) as first, max(_time) as last by src, query\n| convert ctime(first) ctime(last)\n| sort - count",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Each src is a host that resolved the domain; follow up with its proxy/firewall traffic."
      },
      {
        "ctx": "Scanner and attack-tool user agents on web servers",
        "kql": "index=* sourcetype=access_combined earliest=-{{LOOKBACK}}\n| regex useragent=\"(?i)(nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|metasploit)\"\n| stats count, values(uri_path) as paths by clientip, useragent\n| sort - count",
        "read": "Field may be user_agent or http_user_agent in your sourcetype. Scanning alone is noise; a 200 response on exploit paths is not."
      },
      {
        "ctx": "Rare outbound destinations (few connections)",
        "kql": "index=* sourcetype=*firewall* action=allowed earliest=-{{LOOKBACK}}\n| stats count, values(src_ip) as sources by dest_ip, dest_port\n| where count < 5\n| sort count",
        "read": "Rare destinations from servers, or on odd ports, are the leads; check in OSINT."
      },
      {
        "ctx": "Firewall traffic matching a threat-intel index",
        "kql": "index=* sourcetype=*firewall* earliest=-{{LOOKBACK}}\n    [search index=threat_intel earliest=-30d | fields ip | rename ip as dest_ip]\n| stats count, values(action) as action by src_ip, dest_ip\n| sort - count",
        "read": "Change index=threat_intel and the field name to your TI lookup. With Enterprise Security, use the Threat Activity dashboard instead."
      }
    ],
    "fp": "Shared CDN and cloud IPs in threat feeds."
  },
  {
    "id": "splunk-data-health",
    "name": "Splunk: hosts and sources that stopped sending",
    "cat": "SIEM health",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Find hosts and sourcetypes that went quiet, using tstats (fast).",
    "steps": [
      {
        "ctx": "Hosts silent for more than 24 hours",
        "kql": "| tstats latest(_time) as last where index=* earliest=-{{BASELINE}} by host, index\n| where last < relative_time(now(), \"-24h\")\n| eval last=strftime(last, \"%Y-%m-%d %H:%M\")\n| sort last",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Each row is a host that sent data in the baseline window but not in the last day: forwarder down, host off, or logging tampered."
      },
      {
        "ctx": "Daily event count per sourcetype",
        "kql": "| tstats count where index=* earliest=-{{BASELINE}} by _time span=1d, sourcetype\n| timechart span=1d sum(count) by sourcetype limit=15",
        "read": "Drops to zero mean a broken input; spikes may be an attack or a misconfiguration."
      }
    ],
    "fp": "Decommissioned hosts."
  },
  {
    "id": "splunk-linux-host",
    "name": "Splunk: Linux sudo, new users and suspicious commands",
    "cat": "Linux",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1548.003",
      "T1136.001",
      "T1059.004"
    ],
    "playbook": true,
    "summary": "linux_secure and auditd: sudo usage, user creation and reverse-shell style commands.",
    "steps": [
      {
        "ctx": "sudo commands by user and host",
        "kql": "index=* sourcetype=linux_secure \"COMMAND=\" earliest=-{{LOOKBACK}}\n| rex \"sudo:\\s+(?<sudo_user>\\S+)\\s+:.*COMMAND=(?<sudo_cmd>.*)$\"\n| stats count, values(sudo_cmd) as commands by host, sudo_user\n| sort - count",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. sudo to sh/bash, or edits to /etc/shadow and authorized_keys, need confirming."
      },
      {
        "ctx": "New users and password changes",
        "kql": "index=* sourcetype=linux_secure (\"new user\" OR \"useradd\" OR \"password changed\" OR \"usermod\") earliest=-{{BASELINE}}\n| table _time, host, _raw\n| sort - _time",
        "read": "Accounts created outside configuration management are suspicious."
      },
      {
        "ctx": "Reverse shells and droppers (auditd execve)",
        "kql": "index=* sourcetype=linux:audit type=EXECVE earliest=-{{LOOKBACK}}\n| search \"/dev/tcp\" OR \"nc -e\" OR \"bash -i\" OR \"mkfifo\" OR (\"curl\" AND \"| sh\") OR \"base64 -d\"\n| table _time, host, _raw",
        "read": "Needs auditd execve rules and the Linux TA."
      }
    ],
    "fp": "Admin maintenance and automation."
  },
  {
    "id": "splunk-aws-cloudtrail",
    "name": "Splunk: AWS CloudTrail (console logins, IAM, logging disabled)",
    "cat": "Cloud infra",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1078.004",
      "T1098.001",
      "T1562.008"
    ],
    "playbook": true,
    "summary": "aws:cloudtrail: console logins without MFA, new keys and users, and trails being stopped.",
    "steps": [
      {
        "ctx": "Console logins with MFA status",
        "kql": "index=* sourcetype=aws:cloudtrail eventName=ConsoleLogin earliest=-{{LOOKBACK}}\n| table _time, userIdentity.type, userIdentity.arn, sourceIPAddress, additionalEventData.MFAUsed, responseElements.ConsoleLogin, userAgent\n| sort - _time",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Root logins and MFAUsed=No successes first."
      },
      {
        "ctx": "IAM changes",
        "kql": "index=* sourcetype=aws:cloudtrail eventName IN (CreateAccessKey, CreateUser, AttachUserPolicy, PutUserPolicy, CreateLoginProfile, AddUserToGroup) earliest=-{{BASELINE}}\n| table _time, eventName, userIdentity.arn, sourceIPAddress, requestParameters.userName, errorCode\n| sort - _time",
        "read": "New keys or admin policies from unknown IPs indicate takeover."
      },
      {
        "ctx": "Logging disabled",
        "kql": "index=* sourcetype=aws:cloudtrail eventName IN (StopLogging, DeleteTrail, DeleteDetector, DeleteFlowLogs, DisableSecurityHub) earliest=-{{BASELINE}}\n| table _time, eventName, userIdentity.arn, sourceIPAddress",
        "read": "High priority outside a change window."
      }
    ],
    "fp": "Automation roles."
  },
  {
    "id": "splunk-vpn",
    "name": "Splunk: VPN logins (Cisco ASA / AnyConnect, Palo Alto GlobalProtect)",
    "cat": "Identity",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1133",
      "T1078"
    ],
    "playbook": true,
    "summary": "Remote-access VPN sessions for a user and failed VPN logins by source.",
    "steps": [
      {
        "ctx": "VPN sessions for the user",
        "kql": "index=* (sourcetype=cisco:asa (message_id=113039 OR message_id=722022 OR message_id=722023)) OR (sourcetype=\"pan:globalprotect\") user=\"{{ACCOUNT}}\" earliest=-{{BASELINE}}\n| stats count, values(src_ip) as public_ips, values(assigned_ip) as vpn_ips, min(_time) as first, max(_time) as last by user\n| convert ctime(first) ctime(last)",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. Compare public IPs with the user's country; field names differ by vendor TA."
      },
      {
        "ctx": "Failed VPN logins by source",
        "kql": "index=* (sourcetype=cisco:asa (message_id=113015 OR message_id=113005)) OR (sourcetype=\"pan:globalprotect\" status=failure) earliest=-{{LOOKBACK}}\n| stats count as failures, dc(user) as users by src_ip\n| where failures > 10\n| sort - failures",
        "read": "VPN portals are a common spraying target; check whether any user from that IP succeeded."
      }
    ],
    "fp": "Users typing old passwords."
  },
  {
    "id": "splunk-proxy",
    "name": "Splunk: web proxy (who visited a domain, uploads, categories)",
    "cat": "Web & proxy",
    "platform": "Splunk",
    "src": "Splunk (SPL)",
    "sev": "medium",
    "mitre": [
      "T1071.001",
      "T1567"
    ],
    "playbook": true,
    "summary": "Proxy logs (Zscaler, Bluecoat, Squid via CIM Web model): users visiting a domain, large uploads, risky categories.",
    "steps": [
      {
        "ctx": "Users who visited the domain",
        "kql": "index=* tag=web url=\"*{{DOMAIN}}*\" earliest=-{{BASELINE}}\n| stats count, values(action) as action, values(http_method) as methods, min(_time) as first by user, src\n| convert ctime(first)",
        "read": "Splunk SPL, not KQL. Index and sourcetype names differ per environment; change index=* to your index for speed. tag=web uses the CIM Web data model tags; replace with your proxy sourcetype if not tagged. POST after a phishing click may mean credentials were entered."
      },
      {
        "ctx": "Large uploads (possible exfiltration)",
        "kql": "index=* tag=web http_method=POST earliest=-{{LOOKBACK}}\n| stats sum(bytes_out) as bytes_out by user, dest\n| eval MB=round(bytes_out/1048576,1)\n| where MB > 100\n| sort - MB",
        "read": "Uploads to personal cloud storage or file-sharing sites need the user and data owner to confirm."
      }
    ],
    "fp": "Video calls, cloud backups and sync clients."
  },
  {
    "id": "s1-host-activity",
    "name": "SentinelOne: host activity (processes, network, DNS, files)",
    "cat": "Endpoint",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "info",
    "mitre": [
      "T1059",
      "T1071"
    ],
    "playbook": true,
    "summary": "Everything SentinelOne recorded on one endpoint: process starts, network connections, DNS and file creation.",
    "steps": [
      {
        "ctx": "Processes started on the endpoint",
        "kql": "endpoint.name = '{{DEVICE}}' event.type = 'Process Creation'\n| columns event.time, src.process.user, src.process.parent.name, src.process.name, tgt.process.name, tgt.process.cmdline, tgt.process.image.sha256\n| sort -event.time\n| limit 500",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Fields like endpoint.name take one value. Script hosts with encoded or download command lines need a closer look."
      },
      {
        "ctx": "Network connections from the endpoint",
        "kql": "endpoint.name = '{{DEVICE}}' event.category = 'ip'\n| group connections = count(), last = max(event.time) by dst.ip.address, dst.port.number, src.process.name\n| sort -connections\n| limit 200",
        "read": "Rare external IPs from script hosts or unsigned binaries are the ones to check in OSINT."
      },
      {
        "ctx": "DNS lookups from the endpoint",
        "kql": "endpoint.name = '{{DEVICE}}' event.category = 'dns'\n| group lookups = count(), last = max(event.time) by event.dns.request, src.process.name\n| sort -lookups\n| limit 200",
        "read": "Newly registered or random-looking domains stand out."
      },
      {
        "ctx": "Files created in user-writable folders",
        "kql": "endpoint.name = '{{DEVICE}}' event.type = 'File Creation' (tgt.file.path contains 'AppData' or tgt.file.path contains 'Temp' or tgt.file.path contains 'ProgramData' or tgt.file.path contains 'Public')\n| columns event.time, src.process.name, tgt.file.path, tgt.file.sha256\n| sort -event.time\n| limit 300",
        "read": "Executables or scripts dropped by browsers, Office or script hosts are suspicious."
      }
    ],
    "fp": "Updaters and management agents create files and connections constantly; compare with peer endpoints.",
    "platform": "SentinelOne"
  },
  {
    "id": "s1-ioc-hunt",
    "name": "SentinelOne: hunt an IoC across all endpoints (hash, IP, domain)",
    "cat": "Endpoint",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Find every endpoint that ran a file, connected to an IP or looked up a domain.",
    "steps": [
      {
        "ctx": "Which endpoints ran this file (SHA-256)?",
        "kql": "tgt.process.image.sha256 = '{{SHA256}}' or tgt.file.sha256 = '{{SHA256}}'\n| group events = count(), first = min(event.time), last = max(event.time) by endpoint.name, src.process.user\n| sort -events",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Fields like endpoint.name take one value."
      },
      {
        "ctx": "Which endpoints connected to this IP?",
        "kql": "dst.ip.address = '{{IP}}'\n| group connections = count(), last = max(event.time) by endpoint.name, src.process.name, dst.port.number\n| sort -connections",
        "read": "Several endpoints talking to the same external IP widens the incident."
      },
      {
        "ctx": "Which endpoints looked up this domain?",
        "kql": "event.dns.request contains '{{DOMAIN}}'\n| group lookups = count(), last = max(event.time) by endpoint.name, event.dns.request\n| sort -lookups",
        "read": "Put the domain in Domain / URL fragment; subdomains match too."
      }
    ],
    "fp": "Shared infrastructure (CDNs, cloud) shows up on many endpoints; check the owner in OSINT first.",
    "platform": "SentinelOne"
  },
  {
    "id": "s1-logons",
    "name": "SentinelOne: logons and remote access on an endpoint",
    "cat": "Identity",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "info",
    "mitre": [
      "T1078",
      "T1021"
    ],
    "playbook": true,
    "summary": "Who logged on to an endpoint, how, and from where, plus failed attempts.",
    "steps": [
      {
        "ctx": "Logons on the endpoint by user and type",
        "kql": "endpoint.name = '{{DEVICE}}' event.category = 'logins'\n| group logons = count(), last = max(event.time) by event.login.userName, event.login.type, event.login.loginIsSuccessful, src.endpoint.ip.address\n| sort -logons",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Fields like endpoint.name take one value. Failed logons followed by a success for the same user from the same source is a brute-force success; type REMOTE_INTERACTIVE is RDP."
      }
    ],
    "fp": "Service and admin accounts log on frequently; filter known ones.",
    "platform": "SentinelOne"
  },
  {
    "id": "s1-suspicious-process",
    "name": "SentinelOne: Office spawning scripts and encoded PowerShell",
    "cat": "Endpoint",
    "platform": "SentinelOne",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "medium",
    "mitre": [
      "T1059.001",
      "T1204.002",
      "T1218"
    ],
    "playbook": true,
    "summary": "Malicious-document and living-off-the-land patterns in Deep Visibility process events.",
    "steps": [
      {
        "ctx": "Office applications spawning script engines",
        "kql": "event.type = 'Process Creation' src.process.name in:anycase ('winword.exe', 'excel.exe', 'outlook.exe', 'powerpnt.exe', 'onenote.exe') tgt.process.name in:anycase ('powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe', 'rundll32.exe', 'regsvr32.exe')\n| columns event.time, endpoint.name, src.process.user, src.process.name, tgt.process.name, tgt.process.cmdline\n| sort -event.time\n| limit 500",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Any result is high priority (malicious document). Check where the document came from."
      },
      {
        "ctx": "Encoded or download PowerShell",
        "kql": "event.type = 'Process Creation' tgt.process.name in:anycase ('powershell.exe', 'pwsh.exe') tgt.process.cmdline contains:anycase ('-enc', 'FromBase64String', 'DownloadString', 'IEX', '-w hidden')\n| columns event.time, endpoint.name, src.process.user, src.process.name, tgt.process.cmdline\n| sort -event.time\n| limit 500",
        "read": "Decode -enc payloads (Base64 UTF-16LE) before deciding."
      },
      {
        "ctx": "LOLBins with URLs",
        "kql": "event.type = 'Process Creation' tgt.process.name in:anycase ('certutil.exe', 'bitsadmin.exe', 'mshta.exe', 'regsvr32.exe', 'rundll32.exe') tgt.process.cmdline contains:anycase ('http', 'urlcache', '/transfer', 'scrobj')\n| group runs = count(), last = max(event.time) by endpoint.name, tgt.process.name, tgt.process.cmdline\n| sort -runs",
        "read": "Download-and-execute tricks with signed Windows binaries."
      }
    ],
    "fp": "Finance macros and IT scripts."
  },
  {
    "id": "s1-persistence",
    "name": "SentinelOne: persistence (scheduled tasks, Run keys)",
    "cat": "Endpoint",
    "platform": "SentinelOne",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "medium",
    "mitre": [
      "T1053.005",
      "T1547.001"
    ],
    "playbook": true,
    "summary": "Scheduled tasks registered and Run-key values set on an endpoint.",
    "steps": [
      {
        "ctx": "Scheduled tasks registered on the endpoint",
        "kql": "endpoint.name = '{{DEVICE}}' event.category = 'scheduled_task'\n| columns event.time, event.type, task.name, task.path, src.process.name, src.process.user\n| sort -event.time",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Tasks running scripts from AppData, Temp or Public are suspicious."
      },
      {
        "ctx": "Run / RunOnce registry values",
        "kql": "endpoint.name = '{{DEVICE}}' event.category = 'registry' registry.keyPath contains:anycase ('CurrentVersion\\\\Run')\n| columns event.time, event.type, registry.keyPath, registry.value, src.process.name, src.process.user\n| sort -event.time",
        "read": "Values pointing to user-writable folders are the usual malware persistence."
      }
    ],
    "fp": "Software updaters."
  },
  {
    "id": "s1-behavioral-indicators",
    "name": "SentinelOne: behavioral indicators and endpoints reporting",
    "cat": "SIEM health",
    "platform": "SentinelOne",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Which behavioural indicators fired and which endpoints are sending telemetry.",
    "steps": [
      {
        "ctx": "Behavioral indicators by name and endpoint",
        "kql": "event.type = 'Behavioral Indicators'\n| group hits = count(), endpoints = estimate_distinct(endpoint.name), last = max(event.time) by indicator.name, indicator.category\n| sort -hits\n| limit 100",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Indicators like credential dumping or process injection on few endpoints are the ones to open first."
      },
      {
        "ctx": "Last event per endpoint (who stopped reporting?)",
        "kql": "| group last = max(event.time) by endpoint.name, endpoint.os\n| sort last\n| limit 200",
        "read": "Endpoints at the top went quiet first: offline, uninstalled agent or tampering. Use a 7-day range."
      }
    ],
    "fp": "Reference entry."
  },
  {
    "id": "s1-network-web",
    "name": "SentinelOne: URLs, remote-access ports and an IP",
    "cat": "Network",
    "platform": "SentinelOne",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "medium",
    "mitre": [
      "T1071",
      "T1021"
    ],
    "playbook": true,
    "summary": "Who connected to an IP or URL, and outbound remote-access protocols.",
    "steps": [
      {
        "ctx": "Endpoints that connected to the IP",
        "kql": "event.category = 'ip' dst.ip.address = '{{IP}}'\n| group connections = count(), last = max(event.time) by endpoint.name, src.process.name, dst.port.number\n| sort -connections",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Note which process made the connection; browsers are usually benign, script hosts and unsigned binaries are not."
      },
      {
        "ctx": "URLs visited containing the domain",
        "kql": "event.category = 'url' url.address contains:anycase '{{DOMAIN}}'\n| columns event.time, endpoint.name, src.process.name, src.process.user, url.address\n| sort -event.time",
        "read": "URL events exist where SentinelOne captures them (browsers on Windows)."
      },
      {
        "ctx": "Outbound RDP / SMB / SSH / WinRM",
        "kql": "event.category = 'ip' event.network.direction = 'OUTGOING' dst.port.number in (22, 445, 3389, 5985, 5986)\n| group connections = count() by endpoint.name, dst.ip.address, dst.port.number, src.process.name\n| sort -connections",
        "read": "Remote-access protocols from workstations to unusual internal or public addresses show lateral movement."
      }
    ],
    "fp": "Admins and jump hosts."
  },
  {
    "id": "s1-linux",
    "name": "SentinelOne: Linux reverse shells and persistence",
    "cat": "Linux",
    "platform": "SentinelOne",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "medium",
    "mitre": [
      "T1059.004",
      "T1053.003"
    ],
    "playbook": true,
    "summary": "Linux agents: reverse shells, download-and-execute, cron and SSH key changes.",
    "steps": [
      {
        "ctx": "Reverse shells and droppers",
        "kql": "endpoint.os = 'linux' event.type = 'Process Creation' tgt.process.cmdline contains:anycase ('/dev/tcp/', 'nc -e', 'bash -i', 'mkfifo', 'base64 -d', '| sh', '| bash')\n| columns event.time, endpoint.name, src.process.user, src.process.name, tgt.process.cmdline\n| sort -event.time",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Web server users running these mean the app was exploited."
      },
      {
        "ctx": "Cron, sudoers and authorized_keys changes",
        "kql": "endpoint.os = 'linux' event.category = 'file' tgt.file.path contains:anycase ('/etc/cron', '/var/spool/cron', '/etc/sudoers', 'authorized_keys', '/etc/passwd')\n| columns event.time, endpoint.name, event.type, tgt.file.path, src.process.name, src.process.user\n| sort -event.time",
        "read": "Linux persistence and privilege changes; confirm with the server owner."
      }
    ],
    "fp": "Config management tools."
  },
  {
    "id": "s1-dns",
    "name": "SentinelOne: DNS lookups (rare and long domains)",
    "cat": "DNS",
    "platform": "SentinelOne",
    "src": "SentinelOne (PowerQuery / Deep Visibility)",
    "sev": "medium",
    "mitre": [
      "T1071.004"
    ],
    "playbook": true,
    "summary": "Domains resolved across endpoints: rare domains and very long names.",
    "steps": [
      {
        "ctx": "Rare domains across the fleet",
        "kql": "event.category = 'dns'\n| group lookups = count(), endpoints = estimate_distinct(endpoint.name) by event.dns.request\n| filter endpoints = 1\n| sort lookups\n| limit 200",
        "read": "SentinelOne Singularity Data Lake / Deep Visibility PowerQuery, not KQL. Set the time range in the console. Domains seen on only one endpoint are hunting leads; most are benign."
      },
      {
        "ctx": "Very long DNS names (tunnelling)",
        "kql": "event.category = 'dns'\n| let len = len(event.dns.request)\n| filter len > 60\n| group lookups = count() by endpoint.name, event.dns.request\n| sort -lookups",
        "read": "Long random labels under one parent domain suggest data encoded in DNS."
      }
    ],
    "fp": "CDN and telemetry domains."
  },
  {
    "id": "r7-asset-auth",
    "name": "Rapid7: failed and successful logons on assets (Asset Authentication)",
    "cat": "Identity",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1110",
      "T1078"
    ],
    "playbook": true,
    "summary": "Windows / domain authentication: failures by user and source, results for one account, logon types.",
    "steps": [
      {
        "ctx": "Log set: Asset Authentication. Failed logons by user",
        "kql": "where(result ISTARTS-WITH \"FAILED\") groupby(destination_user) calculate(count)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Users with many failures are brute-force targets. If destination_user is empty in your data, use destination_account."
      },
      {
        "ctx": "Log set: Asset Authentication. Failed logons by source IP",
        "kql": "where(result ISTARTS-WITH \"FAILED\") groupby(source_asset_address) calculate(count)",
        "read": "One source failing against many accounts is password spraying."
      },
      {
        "ctx": "Log set: Asset Authentication. All activity for one account",
        "kql": "where(destination_account=NOCASE(\"{{ACCOUNT}}\")) groupby(result, logon_type, source_asset_address)",
        "read": "Put the account in Account name. A SUCCESS from a source that also has many FAILED rows means the brute force worked."
      },
      {
        "ctx": "Log set: Asset Authentication. Failed non-Kerberos logons by destination asset",
        "kql": "where(service NOT IN [krbtgt, kerberos] AND result ISTARTS-WITH \"FAILED\") groupby(destination_asset) calculate(count)",
        "read": "Shows which servers are being attacked."
      }
    ],
    "fp": "Stale saved passwords and service accounts after a password change."
  },
  {
    "id": "r7-ingress-auth",
    "name": "Rapid7: VPN / Microsoft 365 / SSO sign-ins (Ingress Authentication)",
    "cat": "Identity",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1078",
      "T1110.003"
    ],
    "playbook": true,
    "summary": "External logins: by user, by country, from an IP, and successful sign-ins outside the expected countries.",
    "steps": [
      {
        "ctx": "Log set: Ingress Authentication. Sign-ins for one user",
        "kql": "where(user ICONTAINS \"{{UPN}}\") groupby(result, service, source_ip, geoip_country_name)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Shows every service (VPN, Office 365, Okta) the user signed into and from where."
      },
      {
        "ctx": "Log set: Ingress Authentication. Results for an IP",
        "kql": "where(source_ip=\"{{IP}}\") groupby(user, result) calculate(count)",
        "read": "Many users with FAILED_BAD_LOGIN and one SUCCESS from the same IP means a sprayed account was compromised."
      },
      {
        "ctx": "Log set: Ingress Authentication. Unique IPs with failed logins",
        "kql": "where(result=FAILED_BAD_LOGIN) calculate(UNIQUE:source_ip)",
        "read": "A jump in this number is the start of a spraying campaign."
      },
      {
        "ctx": "Log set: Ingress Authentication. Successful sign-ins by country, user agent and service",
        "kql": "where(result=SUCCESS AND geoip_country_code NOT IN [{{COUNTRIES}}]) groupby(user, geoip_country_name, service, user_agent)",
        "read": "Put the home country codes in Countries (e.g. AU). Each row is a success from abroad to confirm with the user."
      },
      {
        "ctx": "Log set: Ingress Authentication. Hourly successes and failures",
        "kql": "where(user ICONTAINS \"{{UPN}}\") groupby(result) calculate(count) timeslice(1h)",
        "read": "Use the chart view to see when the failures turned into a success."
      }
    ],
    "fp": "Travel and VPN egress."
  },
  {
    "id": "r7-ad-admin",
    "name": "Rapid7: Active Directory admin activity (group changes, lockouts, log cleared)",
    "cat": "Identity",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1098",
      "T1136.002",
      "T1070.001"
    ],
    "playbook": true,
    "summary": "Who was added to security groups, privilege escalations, lockouts and audit-log clearing.",
    "steps": [
      {
        "ctx": "Log set: Active Directory Admin Activity. Users added to security groups",
        "kql": "where(action=\"MEMBER_ADDED_TO_SECURITY_GROUP\") groupby(source_user, target_user, group)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. source_user made the change. Additions to admin groups need a change ticket."
      },
      {
        "ctx": "Log set: Active Directory Admin Activity. Privilege escalations",
        "kql": "where(target_account NOT ICONTAINS \"$\" AND action=PRIVILEGE_ESCALATION) groupby(target_account, group, source_user)",
        "read": "Excludes computer accounts ($)."
      },
      {
        "ctx": "Log set: Active Directory Admin Activity. Account lockouts by host (4740)",
        "kql": "where(/4740 EVENT/) groupby(destination_account)",
        "read": "Lockouts across many accounts at once point to spraying."
      },
      {
        "ctx": "Log set: Active Directory Admin Activity. Audit log cleared (1102)",
        "kql": "where(/1102 EVENT/ OR /\\s517 EVENT/)",
        "read": "Any result outside maintenance is high priority."
      }
    ],
    "fp": "Helpdesk and IAM processes."
  },
  {
    "id": "r7-process-start",
    "name": "Rapid7: process start (PowerShell, taskkill, rare processes)",
    "cat": "Endpoint",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1059.001",
      "T1489"
    ],
    "playbook": true,
    "summary": "Endpoint process events from the Insight Agent: PowerShell command lines, processes on a host, hash lookups.",
    "steps": [
      {
        "ctx": "Log set: Process Start Event. Processes on one host",
        "kql": "where(hostname=NOCASE(\"{{DEVICE}}\")) groupby(process.name, process.username, parent_process.name)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Script hosts with an Office or browser parent are the first to open."
      },
      {
        "ctx": "Log set: Process Start Event. PowerShell command lines (not .ps1 files)",
        "kql": "where(process.name=/powershell.exe/i AND process.cmd_line NOT IN [\"null\", /.*ps1.*/i]) groupby(process.cmd_line)",
        "read": "Look for -enc, IEX, DownloadString, -w hidden."
      },
      {
        "ctx": "Log set: Process Start Event. Encoded PowerShell",
        "kql": "where(process.name=/powershell.exe|pwsh.exe/i AND process.cmd_line=/-(e|enc|encodedcommand)\\s/i) groupby(hostname, process.username, process.cmd_line)",
        "read": "Decode the payload (Base64 UTF-16LE)."
      },
      {
        "ctx": "Log set: Process Start Event. taskkill and service stops",
        "kql": "where(process.name=NOCASE(taskkill.exe) OR process.cmd_line ICONTAINS \"net stop\") groupby(hostname, process.cmd_line)",
        "read": "Mass stopping of AV, backup or database services is a ransomware precursor."
      },
      {
        "ctx": "Log set: Process Start Event. Where has this hash run?",
        "kql": "where(process.hashes.sha256=NOCASE(\"{{SHA256}}\")) groupby(hostname, process.name, process.username)",
        "read": "One host = targeted; many hosts = deployed software or a campaign."
      },
      {
        "ctx": "Log set: Process Start Event. Process reputation",
        "kql": "groupby(process.hash_reputation.reputation)",
        "read": "Drill into MALICIOUS or SUSPICIOUS values."
      }
    ],
    "fp": "Admin scripts and software deployment."
  },
  {
    "id": "r7-dns-web",
    "name": "Rapid7: DNS queries and web proxy",
    "cat": "DNS",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1071.004",
      "T1071.001"
    ],
    "playbook": true,
    "summary": "Who resolved a domain, unusual top-level domains, and users visiting a URL.",
    "steps": [
      {
        "ctx": "Log set: DNS Query. Who looked up the domain?",
        "kql": "where(query ICONTAINS \"{{DOMAIN}}\") groupby(asset, user)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Each asset resolved the domain; check its firewall and proxy traffic next."
      },
      {
        "ctx": "Log set: DNS Query. Uncommon top-level domains",
        "kql": "where(public_suffix AND public_suffix NOT IN [com, net, org]) groupby(public_suffix)",
        "read": "TLDs like .top, .xyz, .zip, .ru that your business doesn't use are worth drilling into."
      },
      {
        "ctx": "Log set: Web Proxy. Users who visited the URL",
        "kql": "where(url ICONTAINS \"{{DOMAIN}}\") groupby(user, source_ip)",
        "read": "Field names depend on the proxy (Zscaler, Palo Alto, etc.); check one raw event first."
      }
    ],
    "fp": "CDNs and SaaS subdomains."
  },
  {
    "id": "r7-firewall",
    "name": "Rapid7: firewall traffic (denied, unusual ports, large uploads)",
    "cat": "Firewall",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1071",
      "T1048"
    ],
    "playbook": true,
    "summary": "Traffic to an IP, denied connections, accepted outbound traffic on unusual ports, and top talkers by bytes.",
    "steps": [
      {
        "ctx": "Log set: Firewall. All traffic to or from the IP",
        "kql": "where(source_address=\"{{IP}}\" OR destination_address=\"{{IP}}\") groupby(source_address, destination_address, destination_port, connection_status)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. ACCEPT outbound to a malicious IP needs the internal host investigated; DENY only means the block worked."
      },
      {
        "ctx": "Log set: Firewall. Denied connections by source",
        "kql": "where(connection_status=DENY) groupby(source_address) calculate(count)",
        "read": "Internal sources with many denies may be infected hosts beaconing."
      },
      {
        "ctx": "Log set: Firewall. Accepted outbound on unusual ports",
        "kql": "where(connection_status=\"ACCEPT\" AND direction=\"OUTBOUND\" AND destination_port NOT IN [\"443\", \"80\", \"53\"]) groupby(destination_port)",
        "read": "Drill into rare ports to see source and destination."
      },
      {
        "ctx": "Log set: Firewall. Top outbound destinations by bytes",
        "kql": "where(direction=OUTBOUND) groupby(destination_address) calculate(sum:outgoing_bytes) limit(10)",
        "read": "Large uploads to unknown destinations may be exfiltration."
      },
      {
        "ctx": "Log set: Firewall. External denials (excluding private ranges)",
        "kql": "where(connection_status=DENY AND source_address NOT IN [IP(10.0.0.0/8), IP(172.16.0.0/12), IP(192.168.0.0/16)]) groupby(source_address) calculate(count)",
        "read": "Internet scanners; check if any of them was later accepted."
      }
    ],
    "fp": "Backups and software updates."
  },
  {
    "id": "r7-cloud-o365",
    "name": "Rapid7: Microsoft 365 activity and guest accounts (Cloud Service Activity)",
    "cat": "Cloud apps",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1530",
      "T1136.003"
    ],
    "playbook": true,
    "summary": "What a user did in Microsoft 365, file downloads, and guest (#EXT#) account activity.",
    "steps": [
      {
        "ctx": "Log set: Cloud Service Activity. Actions by the user",
        "kql": "where(source_user ICONTAINS \"{{UPN}}\") groupby(source_json.Workload, action)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. FileDownloaded at volume, AnonymousLinkCreated and inbox rule operations stand out."
      },
      {
        "ctx": "Log set: Cloud Service Activity. Files downloaded by the user",
        "kql": "where(source_user ICONTAINS \"{{UPN}}\" AND action=/FileDownloaded|FileSyncDownloadedFull/) groupby(source_json.SourceFileName) calculate(count)",
        "read": "Hundreds of files in a short window is exfiltration until proven otherwise."
      },
      {
        "ctx": "Log set: Cloud Service Admin Activity. Guest accounts created",
        "kql": "where(action=CREATE_USER AND target_user=/.*\\#EXT\\#.*/i) groupby(source_user, target_user)",
        "read": "Guests invited by non-admins, or to unknown domains, need confirming."
      },
      {
        "ctx": "Log set: Cloud Service Activity. Guest downloads from OneDrive / SharePoint",
        "kql": "where(source_user=/.*\\#EXT\\#.*/i AND action=/FileDownloaded|FileAccessed/) groupby(source_user, source_json.SourceFileName)",
        "read": "Shows what external users actually accessed."
      }
    ],
    "fp": "Project collaboration with partners."
  },
  {
    "id": "r7-email",
    "name": "Rapid7: inbox rules and forwarding (Cloud Service Activity)",
    "cat": "Email",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1114.003",
      "T1564.008"
    ],
    "playbook": true,
    "summary": "Exchange Online inbox rules and mailbox forwarding created by a user.",
    "steps": [
      {
        "ctx": "Log set: Cloud Service Activity. Inbox rules and forwarding for the user",
        "kql": "where(source_json.Workload=Exchange AND action IN [New-InboxRule, Set-InboxRule, UpdateInboxRules, Set-Mailbox] AND source_user ICONTAINS \"{{UPN}}\")",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Open the raw event: Parameters shows ForwardTo, RedirectTo, DeleteMessage and the rule keywords."
      },
      {
        "ctx": "Log set: Cloud Service Activity. All inbox rule creation (last 7 days)",
        "kql": "where(source_json.Workload=Exchange AND action=/InboxRule/i) groupby(source_user, source_json.ClientIP)",
        "read": "Rules created from an IP the user never used before follow most BEC compromises."
      }
    ],
    "fp": "Users' own organising rules."
  },
  {
    "id": "r7-alerts-health",
    "name": "Rapid7: alerts, IDS and log volume",
    "cat": "SIEM health",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "info",
    "mitre": [],
    "playbook": true,
    "summary": "Assets with repeated malware alerts, IDS alerts by severity and total log volume.",
    "steps": [
      {
        "ctx": "Log set: Advanced Malware Alert. Assets with 5+ malicious alerts",
        "kql": "where(severity ICONTAINS \"MALICIOUS\") groupby(asset) having(count>=5)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Repeat offenders may have an active infection the AV keeps re-detecting."
      },
      {
        "ctx": "Log set: IDS Alert. High and critical signatures per asset",
        "kql": "where(severity=\"HIGH\" OR severity=\"CRITICAL\") groupby(asset) calculate(unique:signature)",
        "read": "Assets with several unique high signatures are the priority."
      },
      {
        "ctx": "Any log set. Event volume per hour (is data arriving?)",
        "kql": "calculate(count) timeslice(1h)",
        "read": "Select the log set first. A flat zero means the event source or collector stopped."
      }
    ],
    "fp": "Reference entry."
  },
  {
    "id": "r7-vpn",
    "name": "Rapid7: VPN logins (Ingress Authentication)",
    "cat": "Identity",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1133"
    ],
    "playbook": true,
    "summary": "VPN sessions for an account and VPN logins from outside the expected countries.",
    "steps": [
      {
        "ctx": "Log set: Ingress Authentication (VPN). Logins for the account",
        "kql": "where(service=VPN AND account=NOCASE(\"{{ACCOUNT}}\")) groupby(result, source_ip, geoip_country_name)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Select the VPN event source. Compare countries with where the user works."
      },
      {
        "ctx": "Log set: Ingress Authentication (VPN). Successful VPN logins outside the home countries",
        "kql": "where(service=VPN AND result=SUCCESS AND geoip_country_code NOT IN [{{COUNTRIES}}]) groupby(account, geoip_country_name, source_ip)",
        "read": "Put the home country codes in Countries."
      }
    ],
    "fp": "Travel."
  },
  {
    "id": "r7-linux",
    "name": "Rapid7: Linux process activity (Insight Agent)",
    "cat": "Linux",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1059.004"
    ],
    "playbook": true,
    "summary": "Process Start events from Linux assets: reverse shells, curl/wget droppers, cron and SSH key changes.",
    "steps": [
      {
        "ctx": "Log set: Process Start Event. Reverse shells and droppers on Linux",
        "kql": "where(process.cmd_line ICONTAINS-ANY [\"/dev/tcp/\", \"nc -e\", \"bash -i\", \"mkfifo\", \"base64 -d\", \"| sh\", \"| bash\"]) groupby(hostname, process.username, process.cmd_line)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Web server users running these mean the application was exploited."
      },
      {
        "ctx": "Log set: Process Start Event. Cron, sudoers and SSH keys",
        "kql": "where(process.cmd_line ICONTAINS-ANY [\"crontab\", \"/etc/sudoers\", \"authorized_keys\", \"useradd\"]) groupby(hostname, process.username, process.cmd_line)",
        "read": "Persistence; confirm with the server owner."
      }
    ],
    "fp": "Config management."
  },
  {
    "id": "r7-cloud-infra",
    "name": "Rapid7: AWS / Azure admin activity (Cloud Service Admin Activity)",
    "cat": "Cloud infra",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1098",
      "T1078.004"
    ],
    "playbook": true,
    "summary": "Cloud admin actions from the AWS CloudTrail and Azure event sources.",
    "steps": [
      {
        "ctx": "Log set: Cloud Service Admin Activity. Admin actions by user",
        "kql": "where(source_user ICONTAINS \"{{UPN}}\") groupby(action, source_json.sourceIPAddress)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Use for both AWS and Azure sources; action names follow the provider (CreateAccessKey, roleAssignments/write)."
      },
      {
        "ctx": "Log set: Cloud Service Admin Activity. AWS IAM and logging changes",
        "kql": "where(action IN [CreateAccessKey, CreateUser, AttachUserPolicy, StopLogging, DeleteTrail]) groupby(source_user, action)",
        "read": "StopLogging / DeleteTrail outside a change window is high priority."
      }
    ],
    "fp": "Automation roles."
  },
  {
    "id": "r7-web-proxy",
    "name": "Rapid7: web proxy (domains, users, blocked categories)",
    "cat": "Web & proxy",
    "platform": "Rapid7",
    "src": "Rapid7 InsightIDR (Log Search, LEQL)",
    "sev": "medium",
    "mitre": [
      "T1071.001"
    ],
    "playbook": true,
    "summary": "Web Proxy log set: who visited a domain, blocked traffic and uploads.",
    "steps": [
      {
        "ctx": "Log set: Web Proxy. Users who visited the domain",
        "kql": "where(url ICONTAINS \"{{DOMAIN}}\") groupby(user, source_ip, http_method)",
        "read": "Rapid7 InsightIDR Log Search (LEQL), not KQL. Select the log set named in the context line and set the time range in Log Search. Field names depend on the proxy; check one raw event first. POST after a phishing click may mean credentials were entered."
      },
      {
        "ctx": "Log set: Web Proxy. Blocked requests by user",
        "kql": "where(action=/BLOCK|DENY/i) groupby(user) calculate(count)",
        "read": "A user suddenly hitting many blocked sites may have an infected browser or extension."
      }
    ],
    "fp": "Ad and tracker domains."
  }
];
