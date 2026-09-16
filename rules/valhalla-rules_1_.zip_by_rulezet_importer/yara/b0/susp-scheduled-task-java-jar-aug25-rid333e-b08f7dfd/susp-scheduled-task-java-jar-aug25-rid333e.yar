rule SUSP_Scheduled_Task_Java_JAR_Aug25_RID333E : DEMO FILE SUSP T1053_005 {
   meta:
      description = "Detects scheduled tasks that execute Java JAR files, which is suspicious but not necessarily malicious"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2025-08-07 14:39:31"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, FILE, SUSP, T1053_005"
      minimum_yara = "3.5.0"
      
   strings:
      $a0 = "<Task version=" wide
      $a1 = "xmlns=\"http://schemas.microsoft.com/windows/" wide
      $sa1 = "java.exe</Command>" wide
      $sa2 = "javaw.exe</Command>" wide
      $sb1 = "<Arguments>-jar " wide
   condition: 
      uint16 ( 0 ) == 0xfeff and filesize < 500KB and all of ( $a* ) and 1 of ( $sa* ) and 1 of ( $sb* )
}