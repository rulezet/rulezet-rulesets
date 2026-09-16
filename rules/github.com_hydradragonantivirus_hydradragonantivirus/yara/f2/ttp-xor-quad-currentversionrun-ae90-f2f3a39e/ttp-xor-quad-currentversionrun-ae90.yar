rule TTP_XOR_QUAD_CurrentVersionRun_ae90 {
  strings:
    $key_ae90 = { fd ff [2] d9 f1 [2] f2 dd [2] dc ff [2] c8 e4 [2] c7 fe [2] d9 e3 [2] db e2 [2] c0 e4 [2] dc e3 [2] c0 cc }

  condition:
    any of them
}