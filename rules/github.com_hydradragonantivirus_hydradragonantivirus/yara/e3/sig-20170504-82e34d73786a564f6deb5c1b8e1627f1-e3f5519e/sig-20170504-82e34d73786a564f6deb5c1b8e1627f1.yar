rule sig_20170504_82e34d73786a564f6deb5c1b8e1627f1 {
  meta:
    description = "datamaliciousorder - file 20170504_82e34d73786a564f6deb5c1b8e1627f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c876123adcf85c5af537a5798858694e6f8d86d0fdd4018c2a4accc75c094c85"

  strings:
    $s1 = "this[\"\\x65\\u0076a\\x6c\"](\"\\u006ee\\167\\40\\101\\143\\164\\151v\\145XO\\142j\\145\\u0063t(\\x22\\127\\123\\x63\\162\\x69" ascii
    $s2 = "this[\"\\x65\\u0076a\\x6c\"](\"\\u006ee\\167\\40\\101\\143\\164\\151v\\145XO\\142j\\145\\u0063t(\\x22\\127\\123\\x63\\162\\x69" ascii

  condition:
    uint16(0) == 0x6874 and
    all of them
}