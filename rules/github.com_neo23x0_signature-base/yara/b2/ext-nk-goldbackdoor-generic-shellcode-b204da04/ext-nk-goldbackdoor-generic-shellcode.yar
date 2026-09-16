rule EXT_NK_GOLDBACKDOOR_generic_shellcode {
    meta:
        author= "Silas Cutler (silas@Stairwell.com)"
        description = "Generic detection for shellcode used to drop GOLDBACKDOOR"
        version = "0.1"
        date = "2022-04-21"
        reference = "https://stairwell.com/wp-content/uploads/2022/04/Stairwell-threat-report-The-ink-stained-trail-of-GOLDBACKDOOR.pdf"
        score = 75
        id = "70081d63-0b26-5358-8444-5adc3a44aaa0"
    strings:
        $ = { B9 8E 8A DD 8D 8B F0 E8 ?? ?? ?? ?? FF D0 }
        $ = { B9 8E AB 6F 40 [1-10] 50 [1-10] E8 ?? ?? ?? ?? FF D0 }
    condition:
        all of them
}