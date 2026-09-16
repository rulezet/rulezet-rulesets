rule TTP_XOR_QUAD_CurrentVersionRun_89e6 {
  strings:
    $key_89e6 = { da 89 [2] fe 87 [2] d5 ab [2] fb 89 [2] ef 92 [2] e0 88 [2] fe 95 [2] fc 94 [2] e7 92 [2] fb 95 [2] e7 ba }

  condition:
    any of them
}