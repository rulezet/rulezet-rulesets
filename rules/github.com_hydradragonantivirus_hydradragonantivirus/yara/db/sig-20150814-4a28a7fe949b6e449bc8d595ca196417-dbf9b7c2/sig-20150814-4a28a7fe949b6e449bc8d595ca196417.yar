rule sig_20150814_4a28a7fe949b6e449bc8d595ca196417 {
  meta:
    description = "datamaliciousorder - file 20150814_4a28a7fe949b6e449bc8d595ca196417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d136acc74e5ed2f333312548fd8bbf6dc5c35d366d756796380acb78b7d728c3"

  strings:
    $s1  = "var stroke=\"5557545E0D0A020B24060108130B0B000A1D4A070B09\";function v197() { fqdh('; t'); return gh(); };  function v233() { fq" ascii
    $s2  = "24() { fqdh('send('); return gh(); };  function v103() { fqdh('xo'); return gh(); };  function v203() { fqdh('GET'); return gh()" ascii
    $s3  = "};  function v246() { fqdh(');'); return gh(); };  function v58() { fqdh('s.Exp'); return gh(); };  function v76() { fqdh('e(92)" ascii
    $s4  = "ction v14() { fqdh('com'); return gh(); };  function v146() { fqdh('yp'); return gh(); };  function v59() { fqdh('andE'); return" ascii
    $s5  = "turn gh(); };  function v100() { fqdh('2.X'); return gh(); };  function v139() { fqdh('.Str'); return gh(); };  function v1() { " ascii
    $s6  = ") { fqdh('com'); return gh(); };  function v39() { fqdh('; i'); return gh(); };  function v198() { fqdh('ry '); return gh(); }; " ascii
    $s7  = "eturn gh(); };  function v209() { fqdh('+\"/do'); return gh(); };  function v232() { fqdh(' i'); return gh(); };  function v205(" ascii
    $s8  = ";  function v222() { fqdh('se); '); return gh(); };  function v174() { fqdh('sa'); return gh(); };  function v128() { fqdh(' { '" ascii
    $s9  = "t.Sh'); return gh(); };  function v193() { fqdh('.cl'); return gh(); };  var x = ''; var vi = '';  function v41() { fqdh('{ var'" ascii
    $s10 = "ction v140() { fqdh('eam\"'); return gh(); };  function v165() { fqdh(' dn ='); return gh(); };  function gh() { return vi; };  " ascii
    $s11 = "};  function v243() { fqdh('); '); return gh(); };  function v215() { fqdh('+\"&'); return gh(); };  function v83() { fqdh('()*'" ascii
    $s12 = "fqdh(') {'); return gh(); };  function v234() { fqdh('(dn '); return gh(); };  function v208() { fqdh('b[i]'); return gh(); };  " ascii
    $s13 = "ction v81() { fqdh('h.r'); return gh(); };  function v72() { fqdh('om'); return gh(); };  function v49() { fqdh('ect'); return g" ascii
    $s14 = "};  function v169() { fqdh('osi'); return gh(); };  function v153() { fqdh('xo.'); return gh(); };  function v147() { fqdh('e ='" ascii
    $s15 = "urn gh(); };  function v95() { fqdh('ctive'); return gh(); };  function v61() { fqdh('ronm'); return gh(); };  function v11() { " ascii
    $s16 = "{ fqdh('DB'); return gh(); };  function v16() { fqdh('ate'); return gh(); };  function v68() { fqdh('P%\"'); return gh(); };  fu" ascii
    $s17 = "); return gh(); };  function v185() { fqdh('0); }'); return gh(); };  function v12() { fqdh('dn'); return gh(); };  function v21" ascii
    $s18 = "gh(); };  function v196() { fqdh('}; }'); return gh(); };  function v173() { fqdh(' xa.'); return gh(); };  function v30() { fqd" ascii
    $s19 = "h(); };  function v238() { fqdh('ak; }'); return gh(); };  function v211() { fqdh('nt.p'); return gh(); };  function v143() { fq" ascii
    $s20 = "() { fqdh('=\"+fr'); return gh(); };  function v182() { fqdh('ws.Ru'); return gh(); };  function v22() { fqdh('ihave'); return g" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}