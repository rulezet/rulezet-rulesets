rule CN_Honker_nc_MOVE_RID2D2E : CHINA DEMO SCRIPT SUSP {
   meta:
      description = "Script from disclosed CN Honker Pentest Toolset - file MOVE.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 10:20:51"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, SCRIPT, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s0 = "Destination: http://202.113.20.235/gj/images/2.asp" fullword ascii
      $s1 = "HOST: 202.113.20.235" fullword ascii
      $s2 = "MOVE /gj/images/A.txt HTTP/1.1" fullword ascii
   condition: 
      filesize < 1KB and all of them
}