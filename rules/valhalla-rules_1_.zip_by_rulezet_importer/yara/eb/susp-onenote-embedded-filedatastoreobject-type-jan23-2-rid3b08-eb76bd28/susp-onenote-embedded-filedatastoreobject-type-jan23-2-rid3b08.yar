rule SUSP_OneNote_Embedded_FileDataStoreObject_Type_Jan23_2_RID3B08 : DEMO SUSP {
   meta:
      description = "Detects suspicious embedded file types in OneNote files"
      author = "Florian Roth"
      reference = "https://blog.didierstevens.com/"
      date = "2023-01-27 20:11:51"
      score = 65
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "DEMO, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $a1 = { 00 e7 16 e3 bd 65 26 11 45 a4 c4 8d 4d 0b 7a 9e ac } 
      $s1 = "<HTA:APPLICATION " 
   condition: 
      filesize < 5MB and $a1 and 1 of ( $s* )
}