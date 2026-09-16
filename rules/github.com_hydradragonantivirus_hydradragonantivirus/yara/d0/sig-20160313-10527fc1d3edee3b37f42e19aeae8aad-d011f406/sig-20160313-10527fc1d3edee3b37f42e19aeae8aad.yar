rule sig_20160313_10527fc1d3edee3b37f42e19aeae8aad {
  meta:
    description = "datamaliciousorder - file 20160313_10527fc1d3edee3b37f42e19aeae8aad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8792e42d0ad45ae47a74ed3cad82c012eb9518f712d6bf47dc26fc9f066b2b8"

  strings:
    $s1  = "var RB = true  , deqD = Lyi[7] + Lyi[9] + Lyi[11];" fullword ascii
    $s2  = "return naPshXd[0] + naPshXd[2] + naPshXd[4] + \".F\" + naPshXd[7] + naPshXd[9] + naPshXd[12] + naPshXd[14];" fullword ascii
    $s3  = "var Lyi = (\"2.XMLHTTP VbPzMJs xjwJn XML ream St SGLFFHWM AD imVOcKG O cfFB D\").split(\" \");" fullword ascii
    $s4  = "QUugr.open(DvcWe,BkYbL,false);" fullword ascii
    $s5  = "var naPshXd = \"Sc fAbEjmv r cykIMddCV ipting oGpsLtP bmc ile qXUVFXdmIKuXVp System tO WQnNW Obj DnIMQE ect fzhrPZg\".split(\" " ascii
    $s6  = "function jaty(RWuVw) {" fullword ascii
    $s7  = "function CXuk(zPXTD) {" fullword ascii
    $s8  = "if (RWuVw == 680-480){return true;} else {return false;}" fullword ascii
    $s9  = "return Skj.size;" fullword ascii
    $s10 = "if (BMHyE > 181154-417){return true;} else {return false;}" fullword ascii
    $s11 = "function nqbBH(GMFxFO) {" fullword ascii
    $s12 = "function MAwjY(vPDFwB) {" fullword ascii
    $s13 = "function BIScdePVB() {" fullword ascii
    $s14 = "function mbfvIzI(CPgl) {" fullword ascii
    $s15 = "return PZbHrIk(Sq,IiVKj[498-492]+IiVKj[248-241]+IiVKj[422-414]);" fullword ascii
    $s16 = "if (n >= dIjiC.length) {break;}" fullword ascii
    $s17 = "return GVAs.ExpandEnvironmentStrings(wAHSD);" fullword ascii
    $s18 = "return GMFxFO.position=484-484;" fullword ascii
    $s19 = "function YmPAvwRHE(polzBYXRgsY) {" fullword ascii
    $s20 = "function iKpYuFMW() {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}