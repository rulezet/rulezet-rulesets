rule _20160921_4787695fef4453a16be881bbe0f96c1a_20160921_f1aea308b200_3720 {
  meta:
    description = "datamaliciousorder - from files 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_f1aea308b2000a8d722d0f21c756fabf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash2       = "3175e432bce3be89acef4ff7215de666ea47cac857c8c07ff649c1cdd5484103"

  strings:
    $s1 = "Ti\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KDh\";})(),(functio" ascii
    $s2 = "Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function" ascii
    $s3 = "){return \"Oe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";}" ascii
    $s4 = "ion f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s5 = "function f000(){return \"OUx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){re" ascii
    $s6 = "urn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"EZu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}