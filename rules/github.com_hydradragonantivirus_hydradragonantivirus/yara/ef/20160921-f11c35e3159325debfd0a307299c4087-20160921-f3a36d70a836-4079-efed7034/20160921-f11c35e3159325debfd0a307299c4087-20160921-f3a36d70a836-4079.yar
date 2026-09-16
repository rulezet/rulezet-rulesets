rule _20160921_f11c35e3159325debfd0a307299c4087_20160921_f3a36d70a836_4079 {
  meta:
    description = "datamaliciousorder - from files 20160921_f11c35e3159325debfd0a307299c4087.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"
    hash2       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = ",(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(function f000()" ascii
    $s2 = "n \"Do\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Km\";})(),(fun" ascii
    $s3 = "00(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc" ascii
    $s4 = "00(){return \"MDb\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn" ascii
    $s5 = "n f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"L" ascii
    $s6 = "HJm\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}