rule dat_report_RID2B45 : CHINA DEMO EXE FILE HKTL {
   meta:
      description = "Chinese Hacktool Set - file report.dll"
      author = "Florian Roth"
      reference = "http://tools.zjqhr.com/"
      date = "2015-06-13 08:59:21"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "<a href=\"http://www.xfocus.net\">X-Scan</a>" fullword ascii
      $s2 = "REPORT-ANALYSIS-OF-HOST" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 480KB and all of them
}