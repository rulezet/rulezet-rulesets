rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_50ddf5c101f6_4400 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_50ddf5c101f65dbae1a99b5967b69eaf.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "4d3df92f56e6b5cba10c96e8cd182f92f3c10aceaabe5a4530b70d3fc5873feb"
    hash3       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash4       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash5       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "eturn \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s2 = "ction f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return" ascii
    $s3 = "){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"MDb\";}" ascii
    $s4 = "(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"MDb\";})(),(function f000(){re" ascii
    $s5 = "Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}