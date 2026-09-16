rule sig_20160208_f2faeab6d55e5acdfe7699da4d87de16 {
  meta:
    description = "datamaliciousorder - file 20160208_f2faeab6d55e5acdfe7699da4d87de16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1fa36e007356c6f49855a74afa6d121409f5b012119eb1525a44ca55593841f"

  strings:
    $s1 = "'at' + ('3qOMZ', '3C', 'ies', 'e') + 'ch' + ('poD', '0FMb2', 'GsJu', 'a') + 'n' + ('6iJV', 'J6', 'mp', 'g') + 'e'] = function() " ascii
    $s2 = "    afq6VM1ST['on' + ('kSuLz', 'Ij3', 'jnq', 'r') + 'ea' + ('PcJz', 'gD7', 'B9m', 'd') + 'ys' + ('JxiC14', 'mM', 'p9OM', 't') + " ascii

  condition:
    uint16(0) == 0x0a0d and
    all of them
}