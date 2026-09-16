rule sig_20170422_95f0a090cb014a211484ce040fe598b3 {
  meta:
    description = "datamaliciousorder - file 20170422_95f0a090cb014a211484ce040fe598b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a58beb268e18fabe9d10b8acb95af511c7d87d492e7c713a4e49f7e070ebf0c4"

  strings:
    $s1 = "\"Writ?:28HTTP:2ER\"+" fullword ascii
    $s2 = "\"Fold?rs:28:22T?mplat?\"+" fullword ascii
    $s3 = "function MbJtEjxygCkRfOXDqe(odWqsaDbXNwOpSrQfgM, uboxVwagLvqTezHpDj, AdybJuUOjiNKQlFkct) { " fullword ascii
    $s4 = "return odWqsaDbXNwOpSrQfgM.split(uboxVwagLvqTezHpDj).join(AdybJuUOjiNKQlFkct); }" fullword ascii
    $s5 = "if (mEoCdXRYjqknNxDylsb.FolderExists(\"C\"+\":\\\\w\"+\"INdo\"+\"Ws\") == true) {" fullword ascii
    $s6 = "\"?val(un?scap?(\\\"v\"+" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}