rule TTP_XOR_QUAD_CurrentVersionRun_892a {
  strings:
    $key_892a = { da 45 [2] fe 4b [2] d5 67 [2] fb 45 [2] ef 5e [2] e0 44 [2] fe 59 [2] fc 58 [2] e7 5e [2] fb 59 [2] e7 76 }

  condition:
    any of them
}