rule mal_statelytaurus_969b4b_strings {
  meta:
    author      = "stvemillertime"
    date        = "2024-01-09"
    description = "This looks for odd strings seen in a file cited in this blog https://unit42.paloaltonetworks.com/stately-taurus-targets-philippines-government-cyberespionage/?web_view=true"
    sample      = "969b4b9c889fbec39fae365ff4d7e5b1064dad94030a691e5b9c8479fc63289c"

  strings:
        $str0 = "#\\#\\#\\#\\#\\#\\#" wide
        $str1 = "335a05f9dfa925173ec47ff5c067557d44b6f6da" wide  
  condition:
    uint16(0) == 0x5a4d and
    all of them
}