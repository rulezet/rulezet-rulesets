rule apt_win_iconicstealer: UTA0040
{
    meta:
        author = "threatintel@volexity.com"
        date = "2023-03-30"
        description = "Detect the ICONICSTEALER malware family."
        hash1 = "8ab3a5eaaf8c296080fadf56b265194681d7da5da7c02562953a4cb60e147423"
        reference = "https://www.reddit.com/r/crowdstrike/comments/125r3uu/20230329_situational_awareness_crowdstrike/"
        memory_suitable = 1
        license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"

    strings:
        $str1 = "\\3CXDesktopApp\\config.json" wide
        $str2 = "url, title FROM urls" wide
        $str3 = "url, title FROM moz_places" wide

    condition:
        all of them
}