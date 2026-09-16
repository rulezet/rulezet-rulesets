rule sig_20160314_8191e3c8dc333bca7f4daf7b35dbfcd8 {
  meta:
    description = "datamaliciousorder - file 20160314_8191e3c8dc333bca7f4daf7b35dbfcd8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "832184f020e6e9496a624c1540bb8d891155c5c30750206b483c971d6f4ccb39"

  strings:
    $s1 = "CjSp.open(uZdMKMLx + pzJIHNDSYBBhrrB, rSrYyMdkHd + HKsPfTrrF + OhqJsJjyCwpmYj + bzByvJAAMA + oPeZwCTMf + LNXrmvhxngHv + ZLeqgKCp" ascii
    $s2 = "while (CjSp.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return eeUPjzjCh + OcKyQv + eUgjDdnFcp + oWMArbDrZ + rmjfOfjQz + IXWLydan + meTqmzCqB + ithuEVgAyT" fullword ascii
    $s4 = "bz + jpaMSzpTNjWqmh + BTxY + QtQgzFiVFUrny + YXtgrK, false);" fullword ascii
    $s5 = "var CNlEIFdBikt = new Date();" fullword ascii
    $s6 = "function mjgeMMYtu(fname)" fullword ascii
    $s7 = "function QAWA(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}