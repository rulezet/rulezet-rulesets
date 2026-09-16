rule Empire_invoke_wmi_RID2E0A : DEMO SCRIPT SUSP T1059_001 {
   meta:
      description = "Empire - a pure PowerShell post-exploitation agent - file invoke_wmi.py"
      author = "Florian Roth"
      reference = "https://github.com/PowerShellEmpire/Empire"
      date = "2015-08-06 10:57:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SCRIPT, SUSP, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "(credID, credType, domainName, userName, password, host, sid, notes) = self.mainMenu.credentials.get_credentials(credID)[0]" fullword ascii
      $s2 = "script += \";'Invoke-Wmi executed on \" +computerNames +\"'\"" fullword ascii
      $s3 = "script = \"$PSPassword = \\\"\"+password+\"\\\" | ConvertTo-SecureString -asPlainText -Force;$Credential = New-Object System.Man" ascii
   condition: 
      filesize < 20KB and 2 of them
}