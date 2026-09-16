rule StoneDrill_Service_Install_RID3177 : APT DEMO MIDDLE_EAST SCRIPT T1569_002 {
   meta:
      description = "Rule to detect Batch file from StoneDrill report"
      author = "Florian Roth"
      reference = "https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/"
      date = "2017-03-07 13:23:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2026-03-12"
      tags = "APT, DEMO, MIDDLE_EAST, SCRIPT, T1569_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "127.0.0.1 >nul && sc config" ascii
      $s2 = "LocalService\" && ping -n" ascii fullword
      $s3 = "127.0.0.1 >nul && sc start" ascii fullword
      $s4 = "sc config NtsSrv binpath= \"C:\\WINDOWS\\system32\ntssrvr64.exe" ascii
   condition: 
      filesize < 500 and 2 of them
}