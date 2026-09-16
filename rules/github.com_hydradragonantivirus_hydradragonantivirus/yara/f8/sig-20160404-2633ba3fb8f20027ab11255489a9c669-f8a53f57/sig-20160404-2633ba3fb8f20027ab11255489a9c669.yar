rule sig_20160404_2633ba3fb8f20027ab11255489a9c669 {
  meta:
    description = "datamaliciousorder - file 20160404_2633ba3fb8f20027ab11255489a9c669.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "88f9ae56887a89ee0dd683849c8dc6e91ff90e31d379b643e4f88372776c7aa8"

  strings:
    $s1  = "return SKfMDkw[0] + SKfMDkw[2] + SKfMDkw[4] + \".F\" + SKfMDkw[7] + SKfMDkw[9] + SKfMDkw[12] + SKfMDkw[14];" fullword ascii
    $s2  = "var Ex = true  , yGag = PrD[7] + PrD[9] + PrD[11];" fullword ascii
    $s3  = "kfna.open(gQsrV,OpACP,false);" fullword ascii
    $s4  = "var SKfMDkw = yFsGy(AQvplsbqsq+\" \"+\"System NE kyqZx Obj ZnwwTJ ect OqUmpsA wdWpL\", \" \");" fullword ascii
    $s5  = "var PrD = (\"2.XMLHTTP dAoryjq TAwxF XML ream St VhsFdXmN AD NvawxeQ O dDeI D\").split(\" \");" fullword ascii
    $s6  = "function uPRASqxNl(DkgLY) {" fullword ascii
    $s7  = "return JCrjs.status;" fullword ascii
    $s8  = "return VmCE;" fullword ascii
    $s9  = "function CGhNxdWz(IpA) {" fullword ascii
    $s10 = "return Rau.split(WIHPx);" fullword ascii
    $s11 = "function ohaccXBGl(mNIAWvnRvvV) {" fullword ascii
    $s12 = "function uuYr(JCrjs) {" fullword ascii
    $s13 = "return ThfKuYI;" fullword ascii
    $s14 = "function MXIJ(aaeax,OpACP,gQsrV) {" fullword ascii
    $s15 = "return \"ljJDuYtslwnhXS\";" fullword ascii
    $s16 = "function VHgC(xriQo) {" fullword ascii
    $s17 = "return IpA.size;" fullword ascii
    $s18 = "return yJWugMy;" fullword ascii
    $s19 = "function xJhcFcd(sGAl) {" fullword ascii
    $s20 = "function jkVc(PPEOq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}