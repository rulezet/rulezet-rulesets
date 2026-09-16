rule TTP_XOR_QUAD_CurrentVersionRun_9161 {
  strings:
    $key_9161 = { c2 0e [2] e6 00 [2] cd 2c [2] e3 0e [2] f7 15 [2] f8 0f [2] e6 12 [2] e4 13 [2] ff 15 [2] e3 12 [2] ff 3d }

  condition:
    any of them
}