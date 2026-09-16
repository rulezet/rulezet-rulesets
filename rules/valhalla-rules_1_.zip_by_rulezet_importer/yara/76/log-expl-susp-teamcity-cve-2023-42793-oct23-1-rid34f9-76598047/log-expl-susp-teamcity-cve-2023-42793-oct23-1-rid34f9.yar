rule LOG_EXPL_SUSP_TeamCity_CVE_2023_42793_Oct23_1_RID34F9 : CVE_2023_42793 DEMO EXPLOIT LOG SUSP {
   meta:
      description = "Detects log entries that could indicate a successful exploitation of CVE-2023-42793 on TeamCity servers"
      author = "Florian Roth"
      reference = "https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis"
      date = "2023-10-02 15:53:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CVE_2023_42793, DEMO, EXPLOIT, LOG, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $sa1 = "File edited: " 
      $sa2 = "\\TeamCity\\config\\internal.properties by user with id=" 
      $sb1 = "s.buildServer.ACTIVITIES.AUDIT - server_file_change: File " 
      $sb2 = "\\TeamCity\\config\\internal.properties was modified by \"user with id" 
   condition: 
      all of ( $sa* ) or all of ( $sb* )
}