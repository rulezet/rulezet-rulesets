rule BypassUac2 {
   meta:
      description = "Auto-generated rule - file BypassUac2.zip"
      author = "yarGen Yara Rule Generator"
      hash = "ef3e7dd2d1384ecec1a37254303959a43695df61"
      id = "8b7e49de-9b0a-5dc4-86af-1a854dc649cc"
   strings:
      $s0 = "/BypassUac/BypassUac/BypassUac_Utils.cpp" fullword ascii
      $s1 = "/BypassUac/BypassUacDll/BypassUacDll.aps" fullword ascii
      $s3 = "/BypassUac/BypassUac/BypassUac.ico" fullword ascii
   condition:
      all of them
}