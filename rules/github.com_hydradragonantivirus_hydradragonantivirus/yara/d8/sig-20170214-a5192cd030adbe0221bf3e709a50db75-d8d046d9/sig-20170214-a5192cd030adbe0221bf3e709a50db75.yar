rule sig_20170214_a5192cd030adbe0221bf3e709a50db75 {
  meta:
    description = "datamaliciousorder - file 20170214_a5192cd030adbe0221bf3e709a50db75.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82299d664a1c65fdfefe903562a48e1267eedbe236d88bf3323fdb91904dd791"

  strings:
    $s1  = "var ipkilve = [String, String, String, String, String, String, String, String, WScript, String, String][8][ugulysc + gbixzab + i" ascii
    $s2  = "var mist = [String, String, String, String, String, String, String, String, WScript, String, String][8][ugulysc + gbixzab + ixyj" ascii
    $s3  = "var ipkilve = [String, String, String, String, String, String, String, String, WScript, String, String][8][ugulysc + gbixzab + i" ascii
    $s4  = "var mist = [String, String, String, String, String, String, String, String, WScript, String, String][8][ugulysc + gbixzab + ixyj" ascii
    $s5  = "var bvymohy = ibcoten + ygonme + cqetfyla + bfajidy + opcaf + yddalqe + ekiqq + ztewa + liseqo + sike + tuggojr + ezfumde + vxes" ascii
    $s6  = "zoj + tosasi + bkadvabi + tfutticm + uxvyzm + iwjod + sywyna + uwpic + yrsyhfe + fditi + ijezdud + comy + atux + iwpar + gapa + " ascii
    $s7  = "var kecufi = [String, String, String, \"C:\\\\d\", String, String, String, String, String, String, String][3];" fullword ascii
    $s8  = "var acvakis = [String, String, String, String, String, String, String, String, \"GetD\", String, String, String][8];" fullword ascii
    $s9  = "var ypispybb = [String, String, \"u='^\", String, String, String, String, String, String, String, String, String][2];" fullword ascii
    $s10 = "var ibcoten = [String, String, String, String, String, String, String, \"cmd.\", String, String, String][7];" fullword ascii
    $s11 = "g, String, String, String, String, String, uzuwgut][10](wypzyx + pidkis + acvakis + ehaban + edsohov + ajevzo + ohwop + ypypcy +" ascii
    $s12 = "rdatm + kgeqcolgy + xeqse + ylwihxevx + qbozurpa + pmotlo + jxizizw + rcyfeg + tsahub + joky + wulso + afdib + gfozox + enohsa +" ascii
    $s13 = "xurp + ifebepz + ixen + npyxfegy + plopsizr + kahe + cecynr + duny + wtudxir + tyviqo + azybubc + uwaq + eseli + irjyr + ajufpi " ascii
    $s14 = " + ucjongo + ycis + qcury + lzune + takxofm + dzagonna + sycqycu + xiji + vali + asxyg + odup + unozo + ciqef + ypycec + uzwynby" ascii
    $s15 = "var uxluw = [\"run\", String, String, String, String, String, String, String, String, String, String, String][0];" fullword ascii
    $s16 = "var comy = [String, String, String, \"u+$i\", String, String, String, String, String, String, String][3];" fullword ascii
    $s17 = "//if ([String, String, String, String, String, String, String, String, String, String, new[String, String, String, String, Strin" ascii
    $s18 = "var witelo = [String, String, String, String, String, String, String, String, String, String, \"ucvo\", String][10];" fullword ascii
    $s19 = "var zypramo = [String, String, String, String, String, String, \"='^t\", String, String, String, String, String][6];" fullword ascii
    $s20 = "var rgynugnu = [String, \"$afz\", String, String, String, String, String, String, String, String, String][1];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}