rule Dropper_Hancitor {
  meta:
    authors = "Nick Hoffman & Jeremy Humble - Morphick Inc."
    last_update = "2016-08-19"
    description = "rule to find unpacked Hancitor, useful against memory dumps"
    hash = "587a530cc82ff01d6b2d387d9b558299b0eb36e7e2c274cd887caa39fcc47c6f"
    ref = "http://www.morphick.com/resources/lab-blog/closer-look-hancitor"

  strings:
    

    $arg_parsing = { 83 f? ( 3a | 6c | 64 | 75 | 74 ) 7? ?? b? 01 00 00 00 6b ?? 00 8b ?? 08 0f be 0? ?? }

    

    $pipe_delimit = { b8 01 00 00 00 85 c0 7? ?? 8b 0d ?? ?? ?? ?? 0f be 11 83 fa 7c 7? }

    $fmt_string = "GUID=%I64u&BUILD=%s&INFO=%s&IP=%s&TYPE=1&WIN=%d.%d(%s)"

    

    $connectivty_google_check = { 83 fa 3c 7? ?? b8 01 00 00 00 c1 e0 00 0f be 8c 05 fc fd ff ff 83 f9 21 7? ?? ba 01 00 00 00 d1 e2 0f be 84 15 fc fd ff ff 83 f8 64 7? ?? b9 01 00 00 00 6b d1 03 0f be 84 15 fc fd ff ff 83 f8 6f }

  condition:

    #arg_parsing > 1 or any of ($pipe_delimit, $fmt_string,$connectivty_google_check)

}