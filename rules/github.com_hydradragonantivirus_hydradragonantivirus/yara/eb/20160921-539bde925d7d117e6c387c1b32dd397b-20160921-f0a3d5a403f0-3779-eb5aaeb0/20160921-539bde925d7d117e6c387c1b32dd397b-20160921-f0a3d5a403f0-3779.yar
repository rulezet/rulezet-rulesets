rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_f0a3d5a403f0_3779 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js, 20160921_f3a36d70a83646fa6d4f183bc8e1b1c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"
    hash3       = "331653a2e8936f9d68b3db693057e89f7c2bcfbb22d7e5f8e7dd76dcf11e3ab4"

  strings:
    $s1 = "urn \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s2 = "0(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\"" ascii
    $s3 = "Ts\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Ml\";})(),(function " ascii
    $s4 = " f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KDh" ascii
    $s5 = "MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(functi" ascii
    $s6 = "Eg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}