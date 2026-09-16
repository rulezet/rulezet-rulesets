rule sig_20160322_784ddf92fa6b45b5ab447b3e3e8885bf {
  meta:
    description = "datamaliciousorder - file 20160322_784ddf92fa6b45b5ab447b3e3e8885bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6f8c174bda0b728c9d4c5926b58aaedb48dab86c70384ae34f66c22ea375c93"

  strings:
    $s1  = "return WScript.CreateObject(GmyDD);" fullword ascii
    $s2  = "var Omi = tKnB(kiKE + \"B.\" + XQp[5]+(739278, XQp[4]));" fullword ascii
    $s3  = "return OLBbaft[0] + OLBbaft[2] + OLBbaft[4] + \".F\" + OLBbaft[7] + OLBbaft[9] + OLBbaft[12] + OLBbaft[14];" fullword ascii
    $s4  = "var SD = true  , kiKE = XQp[7] + XQp[9] + XQp[11];" fullword ascii
    $s5  = "GjJR.open(VqEVl,eWNjP,false);" fullword ascii
    $s6  = "var XQp = (\"2.XMLHTTP GeIxWYz ngahl XML ream St QtphwIpf AD TityEKA O QPkx D\").split(\" \");" fullword ascii
    $s7  = "var OLBbaft = kTRyv(vacUFfZPzj+\" \"+\"System pv IEIDZ Obj luLHGC ect eoXvcrO wkWEc\", \" \");" fullword ascii
    $s8  = "function hZMxJBW(QDzQ) {" fullword ascii
    $s9  = "ltb = j; break; " fullword ascii
    $s10 = "function nmNK(blPQh) {" fullword ascii
    $s11 = "function GqKMWzCYV(bKENDXvLVff) {" fullword ascii
    $s12 = "return PJUyrYd(ru,wtfKK[755-749]+wtfKK[305-298]+wtfKK[901-893]);" fullword ascii
    $s13 = "function aSoW(zJFxC,zZjUh) {" fullword ascii
    $s14 = "if (blPQh == 415-215){return true;} else {return false;}" fullword ascii
    $s15 = "return HMLRs.status;" fullword ascii
    $s16 = "function RmUr(CBfPk,eWNjP,VqEVl) {" fullword ascii
    $s17 = "function iEjchwDs(kYyZ) {" fullword ascii
    $s18 = "return mEt.split(QEdDV);" fullword ascii
    $s19 = "function lnpU(iUfwt) {" fullword ascii
    $s20 = "function kTRyv(mEt,QEdDV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}