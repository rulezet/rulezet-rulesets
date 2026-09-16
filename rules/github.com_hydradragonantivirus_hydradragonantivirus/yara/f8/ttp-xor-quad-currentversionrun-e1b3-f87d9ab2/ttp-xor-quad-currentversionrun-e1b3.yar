rule TTP_XOR_QUAD_CurrentVersionRun_e1b3 {
  strings:
    $key_e1b3 = { b2 dc [2] 96 d2 [2] bd fe [2] 93 dc [2] 87 c7 [2] 88 dd [2] 96 c0 [2] 94 c1 [2] 8f c7 [2] 93 c0 [2] 8f ef }

  condition:
    any of them
}