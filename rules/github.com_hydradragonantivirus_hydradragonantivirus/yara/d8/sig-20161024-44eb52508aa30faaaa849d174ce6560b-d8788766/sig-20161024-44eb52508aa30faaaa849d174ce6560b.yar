rule sig_20161024_44eb52508aa30faaaa849d174ce6560b {
  meta:
    description = "datamaliciousorder - file 20161024_44eb52508aa30faaaa849d174ce6560b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ecffd51398c0871e9aa82841e0e840d00bc919b0a893f0cf83633693c80dfe78"

  strings:
    $s1 = "} while (rn++ < ei);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}