rule TTP_XOR_QUAD_CurrentVersionRun_893c {
  strings:
    $key_893c = { da 53 [2] fe 5d [2] d5 71 [2] fb 53 [2] ef 48 [2] e0 52 [2] fe 4f [2] fc 4e [2] e7 48 [2] fb 4f [2] e7 60 }

  condition:
    any of them
}