rule TTP_XOR_QUAD_CurrentVersionRun_9afc {
  strings:
    $key_9afc = { c9 93 [2] ed 9d [2] c6 b1 [2] e8 93 [2] fc 88 [2] f3 92 [2] ed 8f [2] ef 8e [2] f4 88 [2] e8 8f [2] f4 a0 }

  condition:
    any of them
}