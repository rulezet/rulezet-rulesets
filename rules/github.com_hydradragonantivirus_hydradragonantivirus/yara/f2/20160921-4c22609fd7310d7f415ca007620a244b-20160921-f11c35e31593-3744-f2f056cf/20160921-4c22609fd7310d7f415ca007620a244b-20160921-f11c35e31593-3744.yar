rule _20160921_4c22609fd7310d7f415ca007620a244b_20160921_f11c35e31593_3744 {
  meta:
    description = "datamaliciousorder - from files 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "unction f000(){return \"Mt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){retu" ascii
    $s2 = "n f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"K" ascii
    $s3 = "000(){return \"Vj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s4 = "rn \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(" ascii
    $s5 = "{return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})" ascii
    $s6 = "n \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}