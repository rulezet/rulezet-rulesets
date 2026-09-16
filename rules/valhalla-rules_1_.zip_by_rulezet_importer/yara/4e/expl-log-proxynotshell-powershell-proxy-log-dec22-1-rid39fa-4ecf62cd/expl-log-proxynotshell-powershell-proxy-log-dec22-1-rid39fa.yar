rule EXPL_LOG_ProxyNotShell_PowerShell_Proxy_Log_Dec22_1_RID39FA : CVE_2022_41040 CVE_2022_41082 DEMO EXPLOIT LOG SCRIPT T1021_006 T1059_001 T1090 {
   meta:
      description = "Detects traces of exploitation activity in relation to ProxyNotShell MS Exchange vulnerabilities CVE-2022-41040 and CVE-2022-41082"
      author = "Florian Roth"
      reference = "https://www.crowdstrike.com/blog/owassrf-exploit-analysis-and-recommendations/"
      date = "2022-12-22 19:26:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2023-01-26"
      tags = "CVE_2022_41040, CVE_2022_41082, DEMO, EXPLOIT, LOG, SCRIPT, T1021_006, T1059_001, T1090"
      minimum_yara = "3.5.0"
      
   strings:
      $re1 = /,\/[Pp][Oo][Ww][Ee][Rr][Ss][Hh][Ee][Ll][Ll][^\n]{0,50},Kerberos,true,[^\n]{0,50},200,0,,,,[^\n]{0,2000};OnEndRequest\.End\.ContentType=application\/soap\+xml charset UTF-8;S:ServiceCommonMetadata\.HttpMethod=POST;/ ascii wide
      $fp1 = "ClientInfo" ascii wide fullword
      $fp2 = "Microsoft WinRM Client" ascii wide fullword
      $fp3 = "Exchange BackEnd Probes" ascii wide fullword
   condition: 
      $re1 and not 1 of ( $fp* )
}