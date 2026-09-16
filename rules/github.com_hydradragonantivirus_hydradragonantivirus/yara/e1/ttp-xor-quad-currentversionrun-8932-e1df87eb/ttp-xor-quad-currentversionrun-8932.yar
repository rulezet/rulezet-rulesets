rule TTP_XOR_QUAD_CurrentVersionRun_8932 {
  strings:
    $key_8932 = { da 5d [2] fe 53 [2] d5 7f [2] fb 5d [2] ef 46 [2] e0 5c [2] fe 41 [2] fc 40 [2] e7 46 [2] fb 41 [2] e7 6e }

  condition:
    any of them
}