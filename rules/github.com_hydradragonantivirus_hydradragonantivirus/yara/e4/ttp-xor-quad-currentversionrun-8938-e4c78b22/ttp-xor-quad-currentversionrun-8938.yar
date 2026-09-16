rule TTP_XOR_QUAD_CurrentVersionRun_8938 {
  strings:
    $key_8938 = { da 57 [2] fe 59 [2] d5 75 [2] fb 57 [2] ef 4c [2] e0 56 [2] fe 4b [2] fc 4a [2] e7 4c [2] fb 4b [2] e7 64 }

  condition:
    any of them
}