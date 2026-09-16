rule CN_Honker_Webshell_wshell_asp_RID328E : CHINA DEMO T1505_003 WEBSHELL {
   meta:
      description = "Webshell from CN Honker Pentest Toolset - file wshell-asp.txt"
      author = "Florian Roth"
      reference = "Disclosed CN Honker Pentest Toolset"
      date = "2015-06-23 14:10:11"
      score = 70
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "CHINA, DEMO, T1505_003, WEBSHELL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "file1.Write(\"<%response.clear:execute request(\\\"root\\\"):response.End%>\");" fullword ascii
      $s2 = "hello word !  " fullword ascii
      $s3 = "root.asp " fullword ascii
   condition: 
      filesize < 5KB and all of them
}