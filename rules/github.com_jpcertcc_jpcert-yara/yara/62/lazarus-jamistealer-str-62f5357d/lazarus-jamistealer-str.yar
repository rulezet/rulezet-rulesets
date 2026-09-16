rule Lazarus_jamistealer_str {
   meta:
      description = "Stealer targeted macOS and Windows for Lazarus"
      author = "JPCERT/CC Incident Response Group"
      hash = "9abf6b93eafb797a3556bea1fe8a3b7311d2864d5a9a3687fce84bc1ec4a428c"
      hash = "9e3a9dbf10793a27361b3cef4d2c87dbd3662646f4470e5242074df4cb96c6b4"

   strings:
      $str1 = "Download Python Success!" ascii
      $str2 = "Download Client Success!" ascii
      $str3 = "form-data; name=\"multi_file\"; filename=\"%1\"" ascii
      $str4 = "boundary=---------------------------99614912995" ascii
      $str5 = "/.pyp/python.exe" ascii
      $str6 = "/AppData/Local/BraveSoftware/Brave-Browser/User Data" ascii
      $str7 = "/Library/Application Support/BraveSoftware/Brave-Browser" ascii
      $str8 = "/Library/Application Support/com.operasoftware.opera" ascii
      $str9 = "Upload LDB Finshed!!!" ascii
      $str10 = "%1_%2_%3_%4_%5" ascii

   condition:
      ((uint16(0) == 0x5A4D and
       uint32(uint32(0x3c)) == 0x00004550) or
      (uint32(0) == 0xfeedface or
       uint32(0) == 0xcefaedfe or
       uint32(0) == 0xfeedfacf or
       uint32(0) == 0xcffaedfe or
       uint32(0) == 0xcafebabe or
       uint32(0) == 0xbebafeca or
       uint32(0) == 0xcafebabf or
       uint32(0) == 0xbfbafeca)) and
      (5 of ($str*))
}