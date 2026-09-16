rule TTP_XOR_QUAD_CurrentVersionRun_8901 {
  strings:
    $key_8901 = { da 6e [2] fe 60 [2] d5 4c [2] fb 6e [2] ef 75 [2] e0 6f [2] fe 72 [2] fc 73 [2] e7 75 [2] fb 72 [2] e7 5d }

  condition:
    any of them
}