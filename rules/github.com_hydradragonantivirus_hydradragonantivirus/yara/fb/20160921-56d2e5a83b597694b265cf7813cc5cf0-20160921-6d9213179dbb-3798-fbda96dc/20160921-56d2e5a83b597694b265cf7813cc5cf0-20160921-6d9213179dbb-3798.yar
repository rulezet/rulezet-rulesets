rule _20160921_56d2e5a83b597694b265cf7813cc5cf0_20160921_6d9213179dbb_3798 {
  meta:
    description = "datamaliciousorder - from files 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_83dee40cf10de766ec203f9fab018b5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash2       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash3       = "da20d9f2ad414b6bfc45df4fc34c3fc042e1740d759013b54b408f28740fef3f"

  strings:
    $s1 = "unction f000(){return \"GGn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){ret" ascii
    $s2 = ",(function f000(){return \"RVb\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){r" ascii
    $s3 = "turn \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s4 = "Zu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Rh\";})(),(functio" ascii
    $s5 = "\"Yz\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(funct" ascii
    $s6 = "on f000(){return \"Qa\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}