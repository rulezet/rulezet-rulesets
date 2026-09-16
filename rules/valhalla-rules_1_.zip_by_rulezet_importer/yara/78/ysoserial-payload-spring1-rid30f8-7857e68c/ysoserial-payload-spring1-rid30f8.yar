rule Ysoserial_Payload_Spring1_RID30F8 : DEMO EXPLOIT T1203 T1566_001 {
   meta:
      description = "Ysoserial Payloads - file Spring1.bin"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04 13:02:31"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      modified = "2020-11-30"
      hash1 = "bf9b5f35bc1556d277853b71da24faf23cf9964d77245018a0fdf3359f3b1703"
      hash2 = "9c0be107d93096066e82a5404eb6829b1daa6aaa1a7b43bcda3ddac567ce715a"
      hash3 = "8cfa85c16d37fb2c38f277f39cafb6f0c0bd7ee62b14d53ad1dd9cb3f4b25dd8"
      tags = "DEMO, EXPLOIT, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $x1 = "ysoserial/Pwner" ascii
   condition: 
      1 of them
}