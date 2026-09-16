rule TTP_XOR_QUAD_CurrentVersionRun_e7e6 {
  strings:
    $key_e7e6 = { b4 89 [2] 90 87 [2] bb ab [2] 95 89 [2] 81 92 [2] 8e 88 [2] 90 95 [2] 92 94 [2] 89 92 [2] 95 95 [2] 89 ba }

  condition:
    any of them
}