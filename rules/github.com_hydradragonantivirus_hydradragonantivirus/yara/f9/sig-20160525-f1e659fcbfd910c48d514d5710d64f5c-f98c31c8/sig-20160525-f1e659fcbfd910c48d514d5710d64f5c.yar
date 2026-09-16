rule sig_20160525_f1e659fcbfd910c48d514d5710d64f5c {
  meta:
    description = "datamaliciousorder - file 20160525_f1e659fcbfd910c48d514d5710d64f5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6df07c695f2dfbf5698ae067243f8334c7a67144c440a632ad1f7027b60eeba0"

  strings:
    $s1 = "ag + ))(};sdnetg nruter{)(cthg noitcnuf((]rerednerf + cthf + tsilslianbmuhtof + ssorcaf[tpircSW = dnenoisillocb rav\\n;]))(};dee" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}