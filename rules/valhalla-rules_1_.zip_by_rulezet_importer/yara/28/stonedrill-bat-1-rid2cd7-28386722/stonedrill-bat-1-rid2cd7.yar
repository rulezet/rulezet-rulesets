rule StoneDrill_BAT_1_RID2CD7 : APT DEMO FILE MIDDLE_EAST SCRIPT {
   meta:
      description = "Rule to detect Batch file from StoneDrill report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2013-01-01 10:06:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, FILE, MIDDLE_EAST, SCRIPT"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "set u100=" ascii
      $s2 = "set u200=service" ascii fullword
      $s3 = "set u800=%~dp0" ascii fullword
      $s4 = "\"%systemroot%\\system32\\%u100%\"" ascii
      $s5 = "%\" start /b %systemroot%\\system32\\%" ascii
   condition: 
      uint32 ( 0 ) == 0x68636540 and filesize < 500 and 2 of them
}