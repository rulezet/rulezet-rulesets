rule _20160921_13c992e435ed245b1977cea0df2db815_20160921_3ca43590701f_3377 {
  meta:
    description = "datamaliciousorder - from files 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_3ca43590701fad2cb827b5edf3989d00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash2       = "ef7c5701a8646e7803463e9a01e4f2e45cd535f2ed7174e97abde991a779b665"

  strings:
    $s1 = "g\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(functio" ascii
    $s2 = "nction f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s3 = "\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function" ascii
    $s4 = "TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(functi" ascii
    $s5 = "(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";" ascii
    $s6 = "ction f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}