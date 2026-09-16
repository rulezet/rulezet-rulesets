rule EXPL_LOG_ProxyNotShell_OWASSRF_PowerShell_Proxy_Log_Dec22_3_RID3C80 : CVE_2022_41040 CVE_2022_41082 DEMO EXPLOIT LOG SCRIPT T1021_006 T1059_001 T1090 {
   meta:
      description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
      author = "Florian Roth"
      reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
      date = "2022-12-22 21:14:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2022_41040, CVE_2022_41082, DEMO, EXPLOIT, LOG, SCRIPT, T1021_006, T1059_001, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = " POST /powershell - 444 " ascii wide
      $sa2 = " POST /Powershell - 444 " ascii wide
      $sb1 = " - 200 0 0 2" ascii wide
      $fp1 = "ClientInfo" ascii wide fullword
      $fp2 = "Microsoft WinRM Client" ascii wide fullword
      $fp3 = "Exchange BackEnd Probes" ascii wide fullword
   condition: 
      1 of ( $sa* ) and $sb1 and not 1 of ( $fp* )
}