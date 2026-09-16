rule _20160921_8aaa596582e26eec62319f01660d922b_20160921_e949fdc198fe_5508 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash3       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1 = "return \"ZFe\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Kw\";})()" ascii
    $s2 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){retur" ascii
    $s3 = "(){return \"DYx\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s4 = " f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQ" ascii
    $s5 = ")(),(function f000(){return \"Nx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}