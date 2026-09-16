rule TTP_XOR_QUAD_CurrentVersionRun_9a00 {
  strings:
    $key_9a00 = { c9 6f [2] ed 61 [2] c6 4d [2] e8 6f [2] fc 74 [2] f3 6e [2] ed 73 [2] ef 72 [2] f4 74 [2] e8 73 [2] f4 5c }

  condition:
    any of them
}