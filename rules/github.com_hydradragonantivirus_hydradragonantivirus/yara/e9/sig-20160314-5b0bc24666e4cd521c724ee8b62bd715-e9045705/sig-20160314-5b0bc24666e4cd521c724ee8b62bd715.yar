rule sig_20160314_5b0bc24666e4cd521c724ee8b62bd715 {
  meta:
    description = "datamaliciousorder - file 20160314_5b0bc24666e4cd521c724ee8b62bd715.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ba3d2973360889e5330bb3d1d220d762ad6af58b0fad5a9c4d466c8ce3d6bfc"

  strings:
    $s1 = "wBdnF.open(YhjqaJxppRI + dMli, jDekTStMxi + nnrXaQa + QiVTKhCZTPmAjo + PYtGalilYJ + DrbulQnCBoeQGG + XZQBJnvvoeS + rJBM + bsdBve" ascii
    $s2 = "while (wBdnF.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return LZoYCcPyNLHjIf + dxSnXTlOsPfKV + yQcYpWYY + LHUgOiCpoS + cvWzZTMLuvEKS + QgtWVVl + XhzpctWrQ + LmXJtTVpQ + OGwmqjFWqfCfCC" ascii
    $s4 = "oFTKk + VfvmopvswZpnV + ghizMjkX + GFXHRNV + LUEJytwQNBHP + eNDmt + Qin + VyG, false);" fullword ascii
    $s5 = "return LZoYCcPyNLHjIf + dxSnXTlOsPfKV + yQcYpWYY + LHUgOiCpoS + cvWzZTMLuvEKS + QgtWVVl + XhzpctWrQ + LmXJtTVpQ + OGwmqjFWqfCfCC" ascii
    $s6 = "function HpSuvwNt(fname)" fullword ascii
    $s7 = "var tntLnwoCLR = new Date();" fullword ascii
    $s8 = "function kUgiD(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}