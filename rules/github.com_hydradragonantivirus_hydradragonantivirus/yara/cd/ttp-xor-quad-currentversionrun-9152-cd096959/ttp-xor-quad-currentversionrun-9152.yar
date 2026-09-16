rule TTP_XOR_QUAD_CurrentVersionRun_9152 {
  strings:
    $key_9152 = { c2 3d [2] e6 33 [2] cd 1f [2] e3 3d [2] f7 26 [2] f8 3c [2] e6 21 [2] e4 20 [2] ff 26 [2] e3 21 [2] ff 0e }

  condition:
    any of them
}