rule TTP_XOR_QUAD_CurrentVersionRun_9aec {
  strings:
    $key_9aec = { c9 83 [2] ed 8d [2] c6 a1 [2] e8 83 [2] fc 98 [2] f3 82 [2] ed 9f [2] ef 9e [2] f4 98 [2] e8 9f [2] f4 b0 }

  condition:
    any of them
}