rule sig_20160208_9d9dc4f3a2923b663ebcb89bdf4f8d16 {
  meta:
    description = "datamaliciousorder - file 20160208_9d9dc4f3a2923b663ebcb89bdf4f8d16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "689a5011e9aaf95f6b5ae27407c3a56fe91bad81facc9a6ec16b014c8311b073"

  strings:
    $s1 = "    aVKsGQtbA['on' + ('XTx', 'h34aF', 'xP5', 'r') + 'ea' + ('cTI', 'oLW', 'nf', 'd') + 'ys' + ('8C9kz3', 'dkUhuz', '2pFP', 't') " ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}