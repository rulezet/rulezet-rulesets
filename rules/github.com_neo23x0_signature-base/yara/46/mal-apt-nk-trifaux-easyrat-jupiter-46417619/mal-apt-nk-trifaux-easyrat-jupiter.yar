rule MAL_APT_NK_TriFaux_EasyRAT_JUPITER {
   meta:
      author = "CISA.gov"
      description = "Detects a variant of the EasyRAT malware family"
      reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-207a"
      date = "2024-07-25"
      score = 80
      id = "8bd72287-59da-53cf-9015-66149303e59f"
   strings:
      $InitOnce = "InitOnceExecuteOnce"
      $BREAK = { 0D 00 0A 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 2D 00 0D 00 0A }
      $Bytes = "4C,$00,$00,$00,$01,$14,$02,$00,$00,$00,$00,$00,$C0,$00,$00,$00,$00,$00,$00," wide
   condition:
      uint16(0) == 0x5a4d 
      and all of them
}