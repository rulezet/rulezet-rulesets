rule TTP_XOR_QUAD_CurrentVersionRun_b6e6 {
  strings:
    $key_b6e6 = { e5 89 [2] c1 87 [2] ea ab [2] c4 89 [2] d0 92 [2] df 88 [2] c1 95 [2] c3 94 [2] d8 92 [2] c4 95 [2] d8 ba }

  condition:
    any of them
}