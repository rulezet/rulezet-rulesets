rule _20160921_0fe6501a0417801a0e1868963016e9be_20160921_1766f5c818d6_4377 {
  meta:
    description = "datamaliciousorder - from files 20160921_0fe6501a0417801a0e1868963016e9be.js, 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160922_37d3775ea966a92be28550dbc5135955.js, 20160922_6bc7e7cb9bbab9434a7d6dc7718c610f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2926229ccbf6b86ba0ed1aa3ab5b137a43467ffe25d09479a7998c2fdc4b2b30"
    hash2       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash3       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash4       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"
    hash5       = "1ce9e0dc49979ee9e18675311cb94170c53d3836b9d2c99b0e6d51f9cc27fe15"

  strings:
    $s1 = "{return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})()" ascii
    $s2 = "(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(" ascii
    $s3 = "on f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"" ascii
    $s4 = ",(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){" ascii
    $s5 = "rn \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}