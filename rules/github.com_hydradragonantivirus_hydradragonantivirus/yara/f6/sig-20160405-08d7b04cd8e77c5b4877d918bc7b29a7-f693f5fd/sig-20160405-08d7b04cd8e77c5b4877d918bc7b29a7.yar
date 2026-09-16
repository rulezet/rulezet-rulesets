rule sig_20160405_08d7b04cd8e77c5b4877d918bc7b29a7 {
  meta:
    description = "datamaliciousorder - file 20160405_08d7b04cd8e77c5b4877d918bc7b29a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39723f3b87e25263951b31c4b2cf0cb384e2e246238be23e4163c4553d345fb2"

  strings:
    $s1  = "var mH = true  , tFkl = NcC[7] + NcC[9] + NcC[11];" fullword ascii
    $s2  = "return tSWULSf[0] + tSWULSf[2] + tSWULSf[4] + \".F\" + tSWULSf[7] + tSWULSf[9] + tSWULSf[12] + tSWULSf[14];" fullword ascii
    $s3  = "vdXf.open(JILnz,eADkL,false);" fullword ascii
    $s4  = "var NcC = (\"2.XMLHTTP qiBigbe GAkUz XML ream St EkjXHuIY AD ZzHcFZg O TxUB D\").split(\" \");" fullword ascii
    $s5  = "function vqVL(CWQUp) {" fullword ascii
    $s6  = "var xiRfdpv = \"Ybyhgc*OgQ*pt.S\"+\"hell*XkgYWTg*Scri*\";" fullword ascii
    $s7  = "function RdFU(pOrSp,KKEmK) {" fullword ascii
    $s8  = "return oqd.size;" fullword ascii
    $s9  = "function Ciwpd(OPn,hSARv) {" fullword ascii
    $s10 = "function WmnYkTQ(xNhT) {" fullword ascii
    $s11 = "return xNhT[YEgviD[0]];" fullword ascii
    $s12 = "if (ZPfZl > 195013-536){return true;} else {return false;}" fullword ascii
    $s13 = "function FLbhkMzf(oqd) {" fullword ascii
    $s14 = "if(D>=J.length) {break;}" fullword ascii
    $s15 = "function vnHA(QyDns) {" fullword ascii
    $s16 = "function cEMWR(MQWIwj) {" fullword ascii
    $s17 = "return KDYPyEM[0];" fullword ascii
    $s18 = "return sjaZmZw(Tr,KXKEn[396-390]+KXKEn[781-774]+KXKEn[536-528]);" fullword ascii
    $s19 = "function socZr(kfUsVTkN,EIVU) {" fullword ascii
    $s20 = "function iGtjBO(YztQ,xtsRKj) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}