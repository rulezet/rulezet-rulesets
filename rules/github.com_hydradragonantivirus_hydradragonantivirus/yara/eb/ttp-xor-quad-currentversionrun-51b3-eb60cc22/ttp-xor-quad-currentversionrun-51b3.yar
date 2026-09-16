rule TTP_XOR_QUAD_CurrentVersionRun_51b3 {
  strings:
    $key_51b3 = { 02 dc [2] 26 d2 [2] 0d fe [2] 23 dc [2] 37 c7 [2] 38 dd [2] 26 c0 [2] 24 c1 [2] 3f c7 [2] 23 c0 [2] 3f ef }

  condition:
    any of them
}