rule Microcin_Sample_3_RID2D98 : DEMO EXE FILE MAL {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26 10:38:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "4f74a3b67c5ed6f38f08786f1601214412249fe128f12c51525135710d681e1d"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "C:\\Users\\Lenovo\\Desktop\\test\\Release\\test.pdb" fullword ascii
      $s2 = "test, Version 1.0" fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 200KB and all of them )
}