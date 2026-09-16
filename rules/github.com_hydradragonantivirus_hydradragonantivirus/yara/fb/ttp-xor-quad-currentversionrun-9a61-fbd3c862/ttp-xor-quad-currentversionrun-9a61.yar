rule TTP_XOR_QUAD_CurrentVersionRun_9a61 {
  strings:
    $key_9a61 = { c9 0e [2] ed 00 [2] c6 2c [2] e8 0e [2] fc 15 [2] f3 0f [2] ed 12 [2] ef 13 [2] f4 15 [2] e8 12 [2] f4 3d }

  condition:
    any of them
}