rule TTP_XOR_QUAD_CurrentVersionRun_89fc {
  strings:
    $key_89fc = { da 93 [2] fe 9d [2] d5 b1 [2] fb 93 [2] ef 88 [2] e0 92 [2] fe 8f [2] fc 8e [2] e7 88 [2] fb 8f [2] e7 a0 }

  condition:
    any of them
}