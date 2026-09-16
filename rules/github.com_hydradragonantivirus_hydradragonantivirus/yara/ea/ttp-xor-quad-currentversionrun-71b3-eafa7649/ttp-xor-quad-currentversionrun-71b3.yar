rule TTP_XOR_QUAD_CurrentVersionRun_71b3 {
  strings:
    $key_71b3 = { 22 dc [2] 06 d2 [2] 2d fe [2] 03 dc [2] 17 c7 [2] 18 dd [2] 06 c0 [2] 04 c1 [2] 1f c7 [2] 03 c0 [2] 1f ef }

  condition:
    any of them
}