rule LOG_CVE_2021_27065_Exchange_Forensic_Artefacts_RID36CD : CVE_2021_27065 DEMO G0125 LOG {
   meta:
      description = "Detects suspicious log entries that indicate requests as described in reports on HAFNIUM activity"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/#scan-log"
      date = "2021-03-10 17:11:21"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2021-03-15"
      tags = "CVE_2021_27065, DEMO, G0125, LOG"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ServerInfo~" ascii wide
      $sr1 = /\/ecp\/[0-9a-zA-Z]{1,3}\.js/ ascii wide
      $s1 = "/ecp/auth/w.js" ascii wide
      $s2 = "/owa/auth/w.js" ascii wide
      $s3 = "/owa/auth/x.js" ascii wide
      $s4 = "/ecp/main.css" ascii wide
      $s5 = "/ecp/default.flt" ascii wide
      $s6 = "/owa/auth/Current/themes/resources/logon.css" ascii wide
   condition: 
      $x1 and 1 of ( $s* )
}