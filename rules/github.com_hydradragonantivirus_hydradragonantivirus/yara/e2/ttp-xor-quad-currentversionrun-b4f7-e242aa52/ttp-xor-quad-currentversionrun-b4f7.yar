rule TTP_XOR_QUAD_CurrentVersionRun_b4f7 {
  strings:
    $key_b4f7 = { e7 98 [2] c3 96 [2] e8 ba [2] c6 98 [2] d2 83 [2] dd 99 [2] c3 84 [2] c1 85 [2] da 83 [2] c6 84 [2] da ab }

  condition:
    any of them
}