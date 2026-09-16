rule sig_20160525_ea26b3f58b8fbe7e9497e2de157ca464 {
  meta:
    description = "datamaliciousorder - file 20160525_ea26b3f58b8fbe7e9497e2de157ca464.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "935ce11b5cf9d90f099cc4318cc208340986f02ae49f2c2be540f151c84c1ac0"

  strings:
    $s1 = "nard nruter{)(deerdd noitcnuf(+ecapsetihwxelfd+)md(gedotdard+dnenoisillocd+))(};gsmd nruter{)(suidarelcitrapd noitcnuf(+eixodd[ " ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}