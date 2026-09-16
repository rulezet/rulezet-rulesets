rule sig_20160527_c0b5c608a5cd1649b4a40c0ab2c6a7f5 {
  meta:
    description = "datamaliciousorder - file 20160527_c0b5c608a5cd1649b4a40c0ab2c6a7f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d305e37bf187c9bdc1011da8bacae0171f393a98558c1eb57f9834c1cd7c0ad6"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aZHEdyL6z.length;i++)if(i%2==0)x.push(aZHEdyL6z[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}