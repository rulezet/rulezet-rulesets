rule LokiBot_Dropper_Packed_R11_Feb18_RID328F : DEMO FILE MAL T1027_002 {
   meta:
      description = "Semiautomatically generated YARA rule - file scan copy.pdf.r11"
      author = "Florian Roth"
      reference = "https://app.any.run/tasks/401df4d9-098b-4fd0-86e0-7a52ce6ddbf5"
      date = "2018-02-14 14:10:21"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "3b248d40fd7acb839cc592def1ed7652734e0e5ef93368be3c36c042883a3029"
      tags = "DEMO, FILE, MAL, T1027_002"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "C:\\Program Files (x86)\\Microsoft Visual Studio\\VB98\\VB6.OLB" fullword ascii
   condition: 
      uint16 ( 0 ) == 0x0000 and filesize < 2000KB and 1 of them
}