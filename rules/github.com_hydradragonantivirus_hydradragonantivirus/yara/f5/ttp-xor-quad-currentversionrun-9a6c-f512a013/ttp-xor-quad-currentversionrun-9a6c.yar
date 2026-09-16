rule TTP_XOR_QUAD_CurrentVersionRun_9a6c {
  strings:
    $key_9a6c = { c9 03 [2] ed 0d [2] c6 21 [2] e8 03 [2] fc 18 [2] f3 02 [2] ed 1f [2] ef 1e [2] f4 18 [2] e8 1f [2] f4 30 }

  condition:
    any of them
}