rule CN_Honker_sig_3389_3389_3_RID2F08 : CHINA DEMO SCRIPT SUSP T1543_003 {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file 3389.bat"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 11:39:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP, T1543_003"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "echo \"fDenyTSConnections\"=dword:00000000>>3389.reg " fullword ascii
      $s2 = "echo \"PortNumber\"=dword:00000d3d>>3389.reg " fullword ascii
      $s3 = "echo [HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server]>>" ascii
   condition: 
      filesize < 2KB and all of them
}