rule Ysoserial_Payload_RID2DF5 : DEMO EXPLOIT FILE T1203 T1566_001 {
   meta:
      description = "Ysoserial Payloads"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04 10:54:01"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
      hash2 = "adf895fa95526c9ce48ec33297156dd69c3dbcdd2432000e61b2dd34ffc167c7"
      hash3 = "1da04d838141c64711d87695a4cdb4eedfd4a206cc80922a41cfc82df8e24187"
      tags = "DEMO, EXPLOIT, FILE, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ysoserial/payloads/" ascii
      $s1 = "StubTransletPayload" fullword ascii
      $s2 = "Pwnrpw" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xedac and filesize < 40KB and $x1 ) or ( all of them )
}