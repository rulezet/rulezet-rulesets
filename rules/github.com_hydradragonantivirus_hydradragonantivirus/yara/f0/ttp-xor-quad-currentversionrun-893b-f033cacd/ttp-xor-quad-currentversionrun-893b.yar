rule TTP_XOR_QUAD_CurrentVersionRun_893b {
  strings:
    $key_893b = { da 54 [2] fe 5a [2] d5 76 [2] fb 54 [2] ef 4f [2] e0 55 [2] fe 48 [2] fc 49 [2] e7 4f [2] fb 48 [2] e7 67 }

  condition:
    any of them
}