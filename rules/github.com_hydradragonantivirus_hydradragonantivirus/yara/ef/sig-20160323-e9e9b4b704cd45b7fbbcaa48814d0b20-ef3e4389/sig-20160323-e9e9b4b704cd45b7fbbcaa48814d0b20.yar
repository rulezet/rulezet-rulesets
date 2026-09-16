rule sig_20160323_e9e9b4b704cd45b7fbbcaa48814d0b20 {
  meta:
    description = "datamaliciousorder - file 20160323_e9e9b4b704cd45b7fbbcaa48814d0b20.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0ccc0bfa1f7c04a4cab9e75f71640d7bc943c1a4612391a1531af95f8aa661c"

  strings:
    $s1  = "return WScript.CreateObject(bJlOf);" fullword ascii
    $s2  = "return ZqzTCcl[0] + ZqzTCcl[2] + ZqzTCcl[4] + \".F\" + ZqzTCcl[7] + ZqzTCcl[9] + ZqzTCcl[12] + ZqzTCcl[14];" fullword ascii
    $s3  = "var fx = true  , wXok = gfj[7] + gfj[9] + gfj[11];" fullword ascii
    $s4  = "var gfj = (\"2.XMLHTTP JciTddS lqbNR XML ream St LvtxNBxH AD WQsHUBN O EAfk D\").split(\" \");" fullword ascii
    $s5  = "dZvr.open(iJtwG,COBrc,false);" fullword ascii
    $s6  = "var ZqzTCcl = kvBci(GosBRYasnr+\" \"+\"System nm ahfCj Obj moIhkV ect qFAhHTB uEspt\", \" \");" fullword ascii
    $s7  = "if (cfMyI == 643-443){return true;} else {return false;}" fullword ascii
    $s8  = "function LgyFm(loCzMj) {" fullword ascii
    $s9  = "function ddLT(YCtFY,xQpBa) {" fullword ascii
    $s10 = "function jIxthwK(qiom) {" fullword ascii
    $s11 = "function GQqY(CDRgq) {" fullword ascii
    $s12 = "function wbnnh(jyMlfp) {" fullword ascii
    $s13 = "function Vfqy(MdcHv) {" fullword ascii
    $s14 = "return wTk.size;" fullword ascii
    $s15 = "function dcLn(kGpEG) {" fullword ascii
    $s16 = "function kvBci(DeE,OpBOW) {" fullword ascii
    $s17 = "function ZMdU(MHVPC) {" fullword ascii
    $s18 = "return kwVGR;" fullword ascii
    $s19 = "return pAYPPjR(Lf,NmYkb[195-189]+NmYkb[136-129]+NmYkb[494-486]);" fullword ascii
    $s20 = "return DeE.split(OpBOW);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}