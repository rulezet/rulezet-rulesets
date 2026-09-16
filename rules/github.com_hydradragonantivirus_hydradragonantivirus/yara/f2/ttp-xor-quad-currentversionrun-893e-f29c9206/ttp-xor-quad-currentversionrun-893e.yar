rule TTP_XOR_QUAD_CurrentVersionRun_893e {
  strings:
    $key_893e = { da 51 [2] fe 5f [2] d5 73 [2] fb 51 [2] ef 4a [2] e0 50 [2] fe 4d [2] fc 4c [2] e7 4a [2] fb 4d [2] e7 62 }

  condition:
    any of them
}