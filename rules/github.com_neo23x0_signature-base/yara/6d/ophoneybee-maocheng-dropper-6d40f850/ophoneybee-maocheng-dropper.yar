rule OpHoneybee_MaoCheng_Dropper {
   meta:
      description = "Detects MaoCheng dropper from Operation Honeybee"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/JAHZVL"
      date = "2018-03-03"
      hash1 = "35904f482d37f5ce6034d6042bae207418e450f4"
      id = "b163e08e-3892-55f6-ae3e-30d2ba3f4310"
   strings:
      $x1 = "\\MaoCheng\\Release\\" ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 600KB and 1 of them
}