rule sig_20160307_e6e3a49eea99b1c05dc110db0269634f {
  meta:
    description = "datamaliciousorder - file 20160307_e6e3a49eea99b1c05dc110db0269634f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c91cc8103a67ec2e0ceda55b5089f07baccec50bca2a41a5af8971e0c8d9ed6f"

  strings:
    $s1  = "return CNHFGuG[0] + CNHFGuG[2] + CNHFGuG[4] + \".F\" + CNHFGuG[7] + CNHFGuG[9] + CNHFGuG[12] + CNHFGuG[14];" fullword ascii
    $s2  = "var PP = true  , dhXB = yei[7] + yei[9] + yei[11];" fullword ascii
    $s3  = "wyDWA.open(chVJH,AIonc,false);" fullword ascii
    $s4  = "var yei = (\"2.XMLHTTP ErzHjwd NtAra XML ream St qhQLDfLx AD WHqzXCQ O cOpu D\").split(\" \");" fullword ascii
    $s5  = "var CNHFGuG = \"Sc PYQCZaF r LzBJjeMzj ipting Soaujnv saP ile cxylzRLzLkupRM System jc onknA Obj VzXynr ect bgpPsyj\".split(\" " ascii
    $s6  = "if (JFpdj == 497-297){return true;} else {return false;}" fullword ascii
    $s7  = "return djcDU.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s8  = "function rBwz(OOIvA,msjxA) {" fullword ascii
    $s9  = "function jgxMoIDWx(JcspZqKfOZv) {" fullword ascii
    $s10 = "function IQJR(pnVDA) {" fullword ascii
    $s11 = "function oDGO(yYlpJ) {" fullword ascii
    $s12 = "function FvhztBtys(ziRES,qpvmJ,RBIdO,sosU) {" fullword ascii
    $s13 = "function XVuUQNg(RXBB) {" fullword ascii
    $s14 = "function XziFfSdK() {" fullword ascii
    $s15 = "return Nn.ExpandEnvironmentStrings(kPFmY[6]+kPFmY[7]+kPFmY[8]);" fullword ascii
    $s16 = "function DKov(vcrap) {" fullword ascii
    $s17 = "return jyj.size;" fullword ascii
    $s18 = "function xwVz(DPAhO) {" fullword ascii
    $s19 = "function YjwE(wyDWA,AIonc,chVJH) {" fullword ascii
    $s20 = "function eUEF(qYQQQ,GMkPw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}