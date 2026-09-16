rule Ysoserial_Payload_MozillaRhino1_RID335D : DEMO EXPLOIT FILE T1203 T1566_001 {
   meta:
      description = "Ysoserial Payloads - file MozillaRhino1.bin"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04 14:44:41"
      score = 75
      customer = "demo"
      license = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"
      hash1 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
      tags = "DEMO, EXPLOIT, FILE, T1203, T1566_001"
      minimum_yara = "3.5.0"
      
   strings:
      $s3 = "ysoserial.payloads" fullword ascii
   condition: 
      ( uint16 ( 0 ) == 0xedac and filesize < 40KB and all of them )
}