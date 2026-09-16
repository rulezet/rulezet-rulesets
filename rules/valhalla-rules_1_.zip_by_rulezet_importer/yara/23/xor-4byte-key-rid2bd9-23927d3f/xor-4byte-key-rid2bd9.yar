rule XOR_4byte_Key_RID2BD9 : APT DEMO EXE FILE {
   meta:
      description = "Detects an executable encrypted with a 4 byte XOR (also used for Derusbi Trojan)"
      author = "Florian Roth"
      reference = "http://blog.airbuscybersecurity.com/post/2015/11/Newcomers-in-the-Derusbi-family"
      date = "2015-12-15 09:24:01"
      score = 60
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      
      tags = "APT, DEMO, EXE, FILE"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = { 85 C9 74 0A 31 06 01 1E 83 C6 04 49 EB F2 } 
   condition: 
      uint16 ( 0 ) == 0x5a4d and filesize < 900KB and all of them
}