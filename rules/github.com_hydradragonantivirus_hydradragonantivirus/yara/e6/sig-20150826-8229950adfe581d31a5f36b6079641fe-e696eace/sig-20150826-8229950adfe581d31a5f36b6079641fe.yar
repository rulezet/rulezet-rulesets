rule sig_20150826_8229950adfe581d31a5f36b6079641fe {
  meta:
    description = "datamaliciousorder - file 20150826_8229950adfe581d31a5f36b6079641fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee14ac73fbbab9cd222c9bbd91106f6b79fb1ee019fa07ec92996cab7d72a40"

  strings:
    $s1 = "var key = 'Vuttof17';var b = '>\\x19\\x01\\x06 ^\\x11\\x0avW\\x1aFZD\\x0a:\\x5c\\x13\\x01\\x1a\\x0c\\x12XX8U\\x1c\\x18\\x1a\\x14" ascii
    $s2 = "de(b.charCodeAt(gkVFXHhK6) ^ key.charCodeAt(gkVFXHhK7)), gkVFXHhK7++, gkVFXHhK7 == key.length && (gkVFXHhK7 = 0);print(gkVFXHhK5" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}