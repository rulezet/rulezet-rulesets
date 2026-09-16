rule TTP_XOR_QUAD_CurrentVersionRun_9149 {
  strings:
    $key_9149 = { c2 26 [2] e6 28 [2] cd 04 [2] e3 26 [2] f7 3d [2] f8 27 [2] e6 3a [2] e4 3b [2] ff 3d [2] e3 3a [2] ff 15 }

  condition:
    any of them
}