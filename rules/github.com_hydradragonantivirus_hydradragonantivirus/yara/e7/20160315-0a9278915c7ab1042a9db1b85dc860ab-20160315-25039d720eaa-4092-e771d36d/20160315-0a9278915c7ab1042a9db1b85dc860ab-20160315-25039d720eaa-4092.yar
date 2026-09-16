rule _20160315_0a9278915c7ab1042a9db1b85dc860ab_20160315_25039d720eaa_4092 {
  meta:
    description = "datamaliciousorder - from files 20160315_0a9278915c7ab1042a9db1b85dc860ab.js, 20160315_25039d720eaa01eccdcf4e648011e6fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b311cc2951c017a01fde704cdc905b2c1d21b49b6dbadf38ba1696be062f7be4"
    hash2       = "de3b25b0056149b14b3b993a7f593642cfb650d0612bfa28a220972e78eb2e25"

  strings:
    $s1 = " operator === \\\"$=\\\" ? check && result.slice( -check.length ) === check :      operator === \\\"~=\\\" ? ( \\\" \\\" + resul" ascii
    $s2 = "whitespace, \\\" \\\" ) + \\\" \\\" ).indexOf( check ) > -1 :      operator === \\\"|=\\\" ? result === check || result.slice( 0" ascii
    $s3 = "or === \\\"^=\\\" ? check && result.indexOf( check ) === 0 :      operator === \\\"*=\\\" ? check && result.indexOf( check ) > -" ascii
    $s4 = "    forward = type.slice( -4 ) !== \\\"last\\\",     ofType = what === \\\"of-type\\\";\";" fullword ascii
    $s5 = "th + 1 ) === check + \\\"-\\\" :      false;    };   },\";" fullword ascii

  condition:
    ((uint16(0) == 0x6c4a or uint16(0) == 0x7854) and (all of them)
    ) or (all of them)
}