rule EquationGroup_EquationDrug_msgkd {
   meta:
      description = "EquationGroup Malware - file msgkd.ex_"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "25eec68fc9f0d8d1b5d72c9eae7bee29035918e9dcbeab13e276dec4b2ad2a56"
      id = "41019119-9bf4-5a45-b74b-f75ab7738821"
   strings:
      $s1 = "KEysud" fullword ascii
      $s2 = "XWWWPWS" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}