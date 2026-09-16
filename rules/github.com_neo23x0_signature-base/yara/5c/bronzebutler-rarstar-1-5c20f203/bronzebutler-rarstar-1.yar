rule BronzeButler_RarStar_1 {
   meta:
      description = "Detects malware / hacktool sample from Bronze Butler incident"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.secureworks.com/research/bronze-butler-targets-japanese-businesses"
      date = "2017-10-14"
      hash1 = "0fc1b4fdf0dc5373f98de8817da9380479606f775f5aa0b9b0e1a78d4b49e5f4"
      id = "770270b3-6743-5efb-84d8-b63f1df800d9"
   strings:
      $s1 = "Mozilla/4.0+(compatible;+MSIE+8.0;+Windows+NT+6.0;+SV1)" fullword wide
      $s2 = "http://www.google.co.jp" fullword wide
      $s3 = "16D73E22-873D-D58E-4F42-E6055BC9825E" fullword ascii
      $s4 = "\\*.rar" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and 2 of them )
}