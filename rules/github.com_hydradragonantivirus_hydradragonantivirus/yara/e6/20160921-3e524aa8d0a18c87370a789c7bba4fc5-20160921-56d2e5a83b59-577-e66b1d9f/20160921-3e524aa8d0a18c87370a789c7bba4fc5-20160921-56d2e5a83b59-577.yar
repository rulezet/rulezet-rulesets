rule _20160921_3e524aa8d0a18c87370a789c7bba4fc5_20160921_56d2e5a83b59_577 {
  meta:
    description = "datamaliciousorder - from files 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash2       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash3       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash4       = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash5       = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash6       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash7       = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"

  strings:
    $s1  = "n f000(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Q" ascii
    $s2  = "})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KDh\";})(),(function f00" ascii
    $s3  = " f000(){return \"Br\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"RPt" ascii
    $s4  = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Wy\";})(),(function f0" ascii
    $s5  = "(),(function f000(){return \"Oh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s6  = "0(){return \"Nv\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";" ascii
    $s7  = "return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";})()" ascii
    $s8  = " f000(){return \"BQb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"" ascii
    $s9  = "),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f000(" ascii
    $s10 = ",(function f000(){return \"Br\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Nv\";})(),(function f000(){r" ascii
    $s11 = "000(){return \"KIc\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg" ascii
    $s12 = "on f000(){return \"HJm\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Br\";})(),(function f000(){return " ascii
    $s13 = "n f000(){return \"Oe\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"M" ascii
    $s14 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DYx\";}" ascii
    $s15 = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Vj\";})(),(fu" ascii
    $s16 = "{return \"KDh\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s17 = "turn \"IAa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})()," ascii
    $s18 = "n \"ZFe\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s19 = "turn \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()," ascii
    $s20 = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}