rule Hunting_Triangledb_Mod_Strdec {
  meta:
    author      = "@captainGeech42"
    description = "Look for the string decryption routine code in TriangleDB's SMS stealing and mic listening modules."
    date        = "2024-01-08"
    version     = "1"
    DaysofYARA  = "8/100"
    reference   = "https://securelist.com/triangulation-validators-modules/110847/"
    hash        = "c2393fceab76776e19848c2ca3c84bea0ed224ac53206c48f1c5fd525ef66306"

  strings:
    $c1 = {
            08 00 80 52
            29 00 40 39
            29 1d 18 33
            29 29 09 0b
            29 19 49 4a
            29 0d 09 0b
            29 2d 49 4a
            29 3d 09 0b
            0a 05 00 11
            2b 48 6a 38
            6b 01 09 4a
            0b 48 28 38
            e8 03 0a aa
            6a 1d 00 72
            29 01 0a 4a
    }

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and (
      filesize < 2MB and
      all of them
    )
}