rule TTP_XOR_QUAD_CurrentVersionRun_890c {
  strings:
    $key_890c = { da 63 [2] fe 6d [2] d5 41 [2] fb 63 [2] ef 78 [2] e0 62 [2] fe 7f [2] fc 7e [2] e7 78 [2] fb 7f [2] e7 50 }

  condition:
    any of them
}