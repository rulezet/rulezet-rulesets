rule TTP_XOR_QUAD_CurrentVersionRun_9070 {
  strings:
    $key_9070 = { c3 1f [2] e7 11 [2] cc 3d [2] e2 1f [2] f6 04 [2] f9 1e [2] e7 03 [2] e5 02 [2] fe 04 [2] e2 03 [2] fe 2c }

  condition:
    any of them
}