rule Exe_Cloaked_as_ThumbsDb
    {
    meta:
        description = "Detects an executable cloaked as thumbs.db - Malware"
        date = "2014-07-18"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
        score = 50
        id = "ff09f8cf-de5a-50fc-aa0b-c54f7667e246"
    condition:
        uint16(0) == 0x5a4d and filename matches /[Tt]humbs\.db/
}