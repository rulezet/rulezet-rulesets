rule sig_20160526_96c9c838b69961d850735e0bee7b47ec {
  meta:
    description = "datamaliciousorder - file 20160526_96c9c838b69961d850735e0bee7b47ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80846c6257ae21f93c678e9ba396fa1d861bbdd29e2980c06774419044d079b0"

  strings:
    $s1 = "64x\\\\o\" = m4uGAUKLN rav\\n;\"ec6x\\\\\" = v6vOOZYED rav\\n;\"f6x\\\\lc\" = w9jJAFDOR rav\\n;\"56x\\\\s\" = b4vPCCNHP rav'[\"s" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}