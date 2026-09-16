rule TTP_XOR_QUAD_CurrentVersionRun_61b3 {
  strings:
    $key_61b3 = { 32 dc [2] 16 d2 [2] 3d fe [2] 13 dc [2] 07 c7 [2] 08 dd [2] 16 c0 [2] 14 c1 [2] 0f c7 [2] 13 c0 [2] 0f ef }

  condition:
    any of them
}