rule TTP_XOR_QUAD_CurrentVersionRun_8933 {
  strings:
    $key_8933 = { da 5c [2] fe 52 [2] d5 7e [2] fb 5c [2] ef 47 [2] e0 5d [2] fe 40 [2] fc 41 [2] e7 47 [2] fb 40 [2] e7 6f }

  condition:
    any of them
}