rule Microcin_Sample_6_RID2D9B : DEMO EXE FILE MAL {
   meta:
      description = "Malware sample mentioned in Microcin technical report by Kaspersky"
      author = "Florian Roth"
      reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
      date = "2017-09-26 10:39:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "cbd43e70dc55e94140099722d7b91b07a3997722d4a539ecc4015f37ea14a26e"
      hash2 = "871ab24fd6ae15783dd9df5010d794b6121c4316b11f30a55f23ba37eef4b87a"
      tags = "DEMO, EXE, FILE, MAL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "** ERROR ** %s: %s" fullword ascii
      $s2 = "TEMPDATA" fullword wide
      $s3 = "Bruntime error " fullword wide
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 600KB and all of them )
}