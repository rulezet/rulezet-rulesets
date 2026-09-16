rule TTP_XOR_QUAD_CurrentVersionRun_9a71 {
  strings:
    $key_9a71 = { c9 1e [2] ed 10 [2] c6 3c [2] e8 1e [2] fc 05 [2] f3 1f [2] ed 02 [2] ef 03 [2] f4 05 [2] e8 02 [2] f4 2d }

  condition:
    any of them
}