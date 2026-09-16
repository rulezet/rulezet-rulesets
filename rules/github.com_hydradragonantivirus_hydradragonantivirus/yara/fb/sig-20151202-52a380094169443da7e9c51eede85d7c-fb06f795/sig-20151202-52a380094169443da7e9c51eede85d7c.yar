rule sig_20151202_52a380094169443da7e9c51eede85d7c {
  meta:
    description = "datamaliciousorder - file 20151202_52a380094169443da7e9c51eede85d7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa762457b9c0e0a7671af4f8a344c1d228164f0cc9041f926ebd9c90bad5f3c6"

  strings:
    $s1 = "var str=\"5553555E0508010724011C1405101001070C4A070B095E3C5E050A05140514160B001107100D0B0A4A070B095E17565E5550505D5451545750575E" ascii
    $s2 = "ar w8=' = 1;';var l7='ed.co';function v9(){return g3;};var i6=' }; ';var l9='or';var y5='tus ';var s9='t.Sh';var u7='r/';var o4=" ascii
    $s3 = "5='?i';var a5='};';var r4='Cr';var v6='\"kind';var f7=' xa.s';var x2='leng';var f1='cat';var c6='a =';var u2=' (';var b4='; ';va" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}