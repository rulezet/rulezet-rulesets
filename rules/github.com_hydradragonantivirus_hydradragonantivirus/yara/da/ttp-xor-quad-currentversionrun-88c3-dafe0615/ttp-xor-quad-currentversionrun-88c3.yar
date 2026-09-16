rule TTP_XOR_QUAD_CurrentVersionRun_88c3 {
  strings:
    $key_88c3 = { db ac [2] ff a2 [2] d4 8e [2] fa ac [2] ee b7 [2] e1 ad [2] ff b0 [2] fd b1 [2] e6 b7 [2] fa b0 [2] e6 9f }

  condition:
    any of them
}