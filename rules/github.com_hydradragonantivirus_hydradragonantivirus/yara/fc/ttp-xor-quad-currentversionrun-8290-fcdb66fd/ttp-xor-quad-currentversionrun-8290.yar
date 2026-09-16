rule TTP_XOR_QUAD_CurrentVersionRun_8290 {
  strings:
    $key_8290 = { d1 ff [2] f5 f1 [2] de dd [2] f0 ff [2] e4 e4 [2] eb fe [2] f5 e3 [2] f7 e2 [2] ec e4 [2] f0 e3 [2] ec cc }

  condition:
    any of them
}