rule sig_20160525_e106d2de89ad3de26dd3e4524ee4107c {
  meta:
    description = "datamaliciousorder - file 20160525_e106d2de89ad3de26dd3e4524ee4107c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23505fa509b8b4bc40470a87a833b4f61c4bb8e3772507ebf77f5464f16e915d"

  strings:
    $s1 = "dark nruter{)gedotdark(mk noitcnuf;};dnenoisillock nruter{)dnenoisillock(suidarelcitrapk noitcnuf;};gsmk nruter{)gsmk(eixodk noi" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}