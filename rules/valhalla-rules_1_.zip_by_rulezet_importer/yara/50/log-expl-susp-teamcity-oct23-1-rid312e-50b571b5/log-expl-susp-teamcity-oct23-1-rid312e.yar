rule LOG_EXPL_SUSP_TeamCity_Oct23_1_RID312E : DEMO EXPLOIT LOG SUSP T1033 {
   meta:
      description = "Detects log entries that could indicate a successful exploitation of TeamCity servers"
      author = "Florian Roth"
      reference = "https://attackerkb.com/topics/1XEEEkGHzt/cve-2023-42793/rapid7-analysis"
      date = "2023-10-02 13:11:31"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, EXPLOIT, LOG, SUSP, T1033"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = "tbrains.buildServer.ACTIVITIES" 
      $s1 = "External process is launched by user user with id" 
      $s2 = ". Command line: cmd.exe \"/c whoami" 
   condition: 
      all of them
}