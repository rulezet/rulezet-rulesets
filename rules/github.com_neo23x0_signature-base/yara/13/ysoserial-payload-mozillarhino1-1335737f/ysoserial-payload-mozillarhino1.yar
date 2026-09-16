rule Ysoserial_Payload_MozillaRhino1 {
   meta:
      description = "Ysoserial Payloads - file MozillaRhino1.bin"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04"
      hash1 = "0143fee12fea5118be6dcbb862d8ba639790b7505eac00a9f1028481f874baa8"
      id = "c269e032-b6ce-5faa-b3ce-a5304f3e9dab"
   strings:
      $s3 = "ysoserial.payloads" fullword ascii
   condition:
      ( uint16(0) == 0xedac and filesize < 40KB and all of them )
}