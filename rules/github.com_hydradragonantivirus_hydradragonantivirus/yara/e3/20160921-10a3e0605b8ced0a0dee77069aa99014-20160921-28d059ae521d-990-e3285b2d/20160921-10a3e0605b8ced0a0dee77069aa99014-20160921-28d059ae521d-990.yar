rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_28d059ae521d_990 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_28d059ae521dbabe2afdc3bfd464938c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "e141f467019579b96a9cc109c7a3e7efb3b51b1378b450a816089a6ae7d406f7"

  strings:
    $s1  = "000(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs" ascii
    $s2  = " \"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(func" ascii
    $s3  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){ret" ascii
    $s4  = "),(function f000(){return \"Kw\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){" ascii
    $s5  = "{return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"BMj\";})" ascii
    $s6  = "00(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";" ascii
    $s7  = "0(){return \"IAa\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s8  = "tion f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s9  = "0(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp" ascii
    $s10 = "urn \"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(" ascii
    $s11 = "),(function f000(){return \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Kw\";})(),(function f000()" ascii
    $s12 = "Db\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function" ascii
    $s13 = "Db\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s14 = "000(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj" ascii
    $s15 = "n \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(fun" ascii
    $s16 = " f000(){return \"Lo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Z" ascii
    $s17 = "n f000(){return \"MDb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"" ascii
    $s18 = " \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Km\";})(),(func" ascii
    $s19 = "(function f000(){return \"UEg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}