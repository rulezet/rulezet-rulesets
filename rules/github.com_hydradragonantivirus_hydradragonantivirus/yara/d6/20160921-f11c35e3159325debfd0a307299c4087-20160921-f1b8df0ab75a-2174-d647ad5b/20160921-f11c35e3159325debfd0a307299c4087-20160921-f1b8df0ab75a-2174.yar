rule _20160921_f11c35e3159325debfd0a307299c4087_20160921_f1b8df0ab75a_2174 {
  meta:
    description = "datamaliciousorder - from files 20160921_f11c35e3159325debfd0a307299c4087.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"
    hash2       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "n f000(){return \"NYh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s2 = "f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\"" ascii
    $s3 = "turn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYs\";})(),(" ascii
    $s4 = "(){return \"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";}" ascii
    $s5 = "n\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s6 = "(),(function f000(){return \"Go\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s7 = "tion f000(){return \"BQb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s8 = "){return \"Nx\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})" ascii
    $s9 = "f000(){return \"MBb\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}