rule sig_20160525_bcb6100ed171f011d7bb1b3c3d55084b {
  meta:
    description = "datamaliciousorder - file 20160525_bcb6100ed171f011d7bb1b3c3d55084b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7916cecb90cc8683bcbfc45c9f23695d0e41c4ba727e407ffc725cf0f477eaf4"

  strings:
    $s1 = "oo rav\\n;\"13x\\\\-sw\" = ctho rav\\n;\"253x\\\\2\" = rerednero rav\\n;\"t96x\\\\27x\\\\75x\\\\\" = eixodp rav\\n;\"xe45x\\\\e" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}