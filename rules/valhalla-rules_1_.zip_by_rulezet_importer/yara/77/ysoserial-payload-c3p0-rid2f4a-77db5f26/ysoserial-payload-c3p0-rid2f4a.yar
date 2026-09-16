rule Ysoserial_Payload_C3P0_RID2F4A : DEMO EXPLOIT FILE T1203 T1566_001 {
   meta:
      description = "Ysoserial Payloads - file C3P0.bin"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04 11:50:51"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9932108d65e26d309bf7d97d389bc683e52e91eb68d0b1c8adfe318a4ec6e58b"
      tags = "DEMO, EXPLOIT, FILE, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "exploitppppw" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xedac and filesize < 3KB and all of them )
}