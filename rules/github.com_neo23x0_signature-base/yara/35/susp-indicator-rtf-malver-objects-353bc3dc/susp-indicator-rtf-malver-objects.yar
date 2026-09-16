rule SUSP_INDICATOR_RTF_MalVer_Objects {    meta:
      description = "Detects RTF documents with non-standard version and embedding one of the object mostly observed in exploit (e.g. CVE-2017-11882) documents."
      author = "ditekSHen"
      reference = "https://github.com/ditekshen/detection"
      date = "2022-10-20"
      score = 65
      hash1 = "43812ca7f583e40b3e3e92ae90a7e935c87108fa863702aa9623c6b7dc3697a2"
      hash2 = "a31da6c6a8a340901f764586a28bd5f11f6d2a60a38bf60acd844c906a0d44b1"
      id = "2d9d80e0-473e-5aac-a576-8f0002e120e2"
   strings:
            $obj1 = "\\objhtml" ascii
      $obj2 = "\\objdata" ascii
      $obj3 = "\\objupdate" ascii
      $obj4 = "\\objemb" ascii
      $obj5 = "\\objautlink" ascii
      $obj6 = "\\objlink" ascii
   condition:
      uint32(0) == 0x74725c7b and (
                           (not uint8(4) == 0x66 or not uint8(5) == 0x31 or not uint8(6) == 0x5c) 
         and 1 of ($obj*)
      )
}