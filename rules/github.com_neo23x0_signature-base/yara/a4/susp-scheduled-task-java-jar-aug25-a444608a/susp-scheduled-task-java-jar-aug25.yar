rule SUSP_Scheduled_Task_Java_JAR_Aug25 {
   meta:
      description = "Detects scheduled tasks that execute Java JAR files, which is suspicious but not necessarily malicious"
      author = "Florian Roth"
      date = "2025-08-07"
      score = 60
      reference = "Internal Research"
      hash = "7c5999082d9c5f3dd342ca05191311ddd1e24ba7675d1e9763fb4d962be3a933"
   strings:
      $a0 = "<Task version=" wide
      $a1 = "xmlns=\"http://schemas.microsoft.com/windows/" wide

      $sa1 = "java.exe</Command>" wide
      $sa2 = "javaw.exe</Command>" wide

      $sb1 = "<Arguments>-jar " wide
   condition:
      uint16(0) == 0xfeff
      and filesize < 500KB
      and all of ($a*)
      and 1 of ($sa*)
      and 1 of ($sb*)
}