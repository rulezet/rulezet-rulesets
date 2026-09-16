rule TTP_XOR_QUAD_CurrentVersionRun_8922 {
  strings:
    $key_8922 = { da 4d [2] fe 43 [2] d5 6f [2] fb 4d [2] ef 56 [2] e0 4c [2] fe 51 [2] fc 50 [2] e7 56 [2] fb 51 [2] e7 7e }

  condition:
    any of them
}