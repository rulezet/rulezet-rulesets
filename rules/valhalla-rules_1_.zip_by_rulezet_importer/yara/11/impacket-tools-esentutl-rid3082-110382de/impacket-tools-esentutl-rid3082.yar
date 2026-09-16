rule Impacket_Tools_esentutl_RID3082 : DEMO EXE FILE HKTL {
   meta:
      description = "Compiled Impacket Tools"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07 12:42:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "70d854953d3ebb2c252783a4a103ba0e596d6ab447f238af777fb37d2b64c0cd"
      tags = "DEMO, EXE, FILE, HKTL"
      minimum_yara = "3.5.0"
      
   strings:
      $s1 = "impacket.ese(" ascii
      $s2 = "sesentutl" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0x5a4d and filesize < 11000KB and all of them )
}