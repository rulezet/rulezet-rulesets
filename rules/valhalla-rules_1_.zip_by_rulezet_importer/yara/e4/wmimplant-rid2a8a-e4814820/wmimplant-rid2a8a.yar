rule WMImplant_RID2A8A : DEMO SCRIPT T1047 T1059 T1059_001 {
   meta:
      description = "Detects WMI implant- file WMImplant_RID2A8A.ps1"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/03/wmimplant_a_wmi_ba.html"
      date = "2017-03-24 06:41:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "860d7c237c2395b4f51b8c9bd0ee6cab06af38fff60ce3563d160d50c11d2f78"
      tags = "DEMO, SCRIPT, T1047, T1059, T1059_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "Invoke-ProcessPunisher -Creds $RemoteCredential" fullword ascii
      $x2 = "$Target -query \"SELECT * FROM Win32_NTLogEvent WHERE (logfile='security')" ascii
      $x3 = "WMImplant_RID2A8A -Creds" fullword ascii
      $x4 = "-Download -RemoteFile C:\\passwords.txt" ascii
      $x5 = "-Command 'powershell.exe -command \"Enable-PSRemoting" fullword ascii
      $x6 = "Invoke-WMImplant_RID2A8A" fullword ascii
   condition: 
      1 of them
}