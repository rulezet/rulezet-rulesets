rule TTP_XOR_QUAD_CurrentVersionRun_88d9 {
  strings:
    $key_88d9 = { db b6 [2] ff b8 [2] d4 94 [2] fa b6 [2] ee ad [2] e1 b7 [2] ff aa [2] fd ab [2] e6 ad [2] fa aa [2] e6 85 }

  condition:
    any of them
}