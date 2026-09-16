rule TTP_XOR_QUAD_CurrentVersionRun_f1b3 {
  strings:
    $key_f1b3 = { a2 dc [2] 86 d2 [2] ad fe [2] 83 dc [2] 97 c7 [2] 98 dd [2] 86 c0 [2] 84 c1 [2] 9f c7 [2] 83 c0 [2] 9f ef }

  condition:
    any of them
}