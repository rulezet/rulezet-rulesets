rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_4c22609fd731_328 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash4       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash5       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash6       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1  = "urn \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s2  = "nction f000(){return \"Go\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Kw\";})(),(function f000(){retur" ascii
    $s3  = "),(function f000(){return \"Oe\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){r" ascii
    $s4  = "rn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"PTi\";})(),(fu" ascii
    $s5  = " \"MBb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s6  = "turn \"Lp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s7  = "tion f000(){return \"Br\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return " ascii
    $s8  = " f000(){return \"Tn\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Y" ascii
    $s9  = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"U" ascii
    $s10 = "(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Um\";})(),(function f000()" ascii
    $s11 = "\"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii
    $s12 = "urn \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})()," ascii
    $s13 = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f" ascii
    $s14 = "00(){return \"Sj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";" ascii
    $s15 = "rn \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(fun" ascii
    $s16 = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Tb\";})(),(function f" ascii
    $s17 = "(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";}" ascii
    $s18 = "0(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s19 = " \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Br\";})(),(func" ascii
    $s20 = "eturn \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}