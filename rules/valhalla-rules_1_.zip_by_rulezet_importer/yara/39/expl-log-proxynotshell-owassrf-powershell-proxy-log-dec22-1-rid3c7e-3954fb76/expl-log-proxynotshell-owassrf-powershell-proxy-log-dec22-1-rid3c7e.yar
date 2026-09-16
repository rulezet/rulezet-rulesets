rule EXPL_LOG_ProxyNotShell_OWASSRF_PowerShell_Proxy_Log_Dec22_1_RID3C7E : CVE_2022_41040 CVE_2022_41082 DEMO EXPLOIT LOG SCRIPT T1021_006 T1059_001 T1090 {
   meta:
      description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
      author = "Florian Roth"
      reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
      date = "2022-12-22 21:14:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2022_41040, CVE_2022_41082, DEMO, EXPLOIT, LOG, SCRIPT, T1021_006, T1059_001, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "/owa/mastermailbox%40outlook.com/powershell" ascii wide
      $sa1 = " 200 " ascii wide
      $sa2 = " POST " ascii wide
      $fp1 = "ClientInfo" ascii wide fullword
      $fp2 = "Microsoft WinRM Client" ascii wide fullword
      $fp3 = "Exchange BackEnd Probes" ascii wide fullword
   condition: 
      all of ( $s* ) and not 1 of ( $fp* )
}