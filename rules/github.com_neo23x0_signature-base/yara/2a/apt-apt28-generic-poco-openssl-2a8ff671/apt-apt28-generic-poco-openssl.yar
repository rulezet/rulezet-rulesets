rule APT_APT28_generic_poco_openssl {
    meta:
        description = "Rule to detect statically linked POCO and OpenSSL libraries (COULD be Drovorub related and should be further investigated)"
        author = "NSA / FBI"
        reference = "https://www.nsa.gov/news-features/press-room/Article/2311407/nsa-and-fbi-expose-russian-previously-undisclosed-malware-drovorub-in-cybersecu/"
        date = "2020-08-13"
        score = 50
    strings:
        $mw1 = { 89 F1 48 89 FE 48 89 D7 48 F7 C6 FF FF FF FF 0F 84 6B 02 00 00 48 F7 C7
                 FF FF FF FF 0F 84 5E 02 00 00 48 8D 2D }

        $mw2 = { 41 54 49 89 D4 55 53 F6 47 19 04 48 8B 2E 75 08 31 DB F6 45 00 03 75 } 
        $mw3 = { 85C0BA15000000750989D05BC30F1F44 0000BE }
          
        $mw4 = { 53 8A 47 08 3C 06 74 21 84 C0 74 1D 3C 07 74 20 B9 ?? ?? ?? ?? BA FD 03 
                 00 00 BE ?? ?? ?? ?? BF ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 E8 06 3C 01 77 2B 48 8B 1F 48 8B 73 
                 10 48 89 DF E8 ?? ?? ?? ?? 48 8D 43 08 48 C7 43 10 00 00 00 00 48 C7 43 28 00 00 00 00 48 
                 89 43 18 48 89 43 20 5B C3 }
    condition:
        all of them
}