rule sig_20160517_f4efae804040ada7f051fe3fbbe40fd1 {
  meta:
    description = "datamaliciousorder - file 20160517_f4efae804040ada7f051fe3fbbe40fd1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56e6b6145850ceb06c31e11c75520ca28cf32a8852bfc58be27a86a8d99ab178"

  strings:
    $s1 = "var turbcd='vymwwzaparabrvaiod dyym4uzdloxaoqmj1infmjc4nigdm4yvryj4nuiwhdo2o2qrj2g4lzbqvxa=djmir\\'aymuxtctrjqckzrr1npd3sgie42i1" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}