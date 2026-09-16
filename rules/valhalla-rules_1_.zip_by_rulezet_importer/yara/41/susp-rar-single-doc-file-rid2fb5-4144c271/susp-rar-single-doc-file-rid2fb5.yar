rule SUSP_RAR_Single_Doc_File_RID2FB5 : DEMO FILE SUSP {
   meta:
      description = "Detects suspicious RAR files that contain nothing but a single .doc file"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-07-11 12:08:41"
      score = 40
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "51a568ac3ceb6bc4a4a123af9ca383a32bac0f630b17a1cc99e45ff8002727b1"
      hash2 = "f9eddbebf9c41089d7507291adbaac8a4bcebffcd960f838d8a9648194d38a4a"
      tags = "DEMO, FILE, SUSP"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = ".doc" 
   condition: 
      uint16 ( 0 ) == 0x6152 and filesize < 4000KB and $s1 at ( uint16 ( 5 ) + uint16 ( uint16 ( 5 ) + 5 ) + uint16 ( uint16 ( 5 ) + uint16 ( uint16 ( 5 ) + 5 ) + 5 ) - 9 ) and ( uint16 ( 5 ) + uint16 ( uint16 ( 5 ) + 5 ) + uint16 ( uint16 ( 5 ) + uint16 ( uint16 ( 5 ) + 5 ) + 5 ) + uint32 ( uint16 ( 5 ) + uint16 ( uint16 ( 5 ) + 5 ) + 7 ) > filesize - 8 )
}