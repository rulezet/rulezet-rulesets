rule sig_20170306_fbb7e6840238ac85698cc001df13289a {
  meta:
    description = "datamaliciousorder - file 20170306_fbb7e6840238ac85698cc001df13289a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34a84acba06b0296b86f85d46a7d9a3b9f8d4187cbb5c01296ec7297789606c0"

  strings:
    $s1 = "var x = new Array(\"tryitontechnology.com\", \"chuckonomics.com\", \"jleaf.se\", \"writewhenyougetwork.com\", \"mirmax.ru\");" fullword ascii
    $s2 = "e[raspbna2s[19-29+10]](rak+\"\"+\"\"+hfpi+\"\"+\"\"+\"\"+\"T\", t4 + \":\"+ter+ter+x[i]+ter+\"c\"+\"o\"+\"u\"+\"n\"+\"t\"+\"er/?" ascii
    $s3 = "return new ActiveXObject(g2);" fullword ascii
    $s4 = "var vDJmB = function(){" fullword ascii
    $s5 = "function mesuto() {" fullword ascii
    $s6 = "function reqty(fdga) { eval(fdga); }" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}