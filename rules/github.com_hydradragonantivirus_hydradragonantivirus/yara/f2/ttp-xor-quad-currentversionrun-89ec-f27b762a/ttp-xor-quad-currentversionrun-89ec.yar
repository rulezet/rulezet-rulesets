rule TTP_XOR_QUAD_CurrentVersionRun_89ec {
  strings:
    $key_89ec = { da 83 [2] fe 8d [2] d5 a1 [2] fb 83 [2] ef 98 [2] e0 82 [2] fe 9f [2] fc 9e [2] e7 98 [2] fb 9f [2] e7 b0 }

  condition:
    any of them
}