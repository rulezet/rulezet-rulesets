rule TTP_XOR_QUAD_CurrentVersionRun_912b {
  strings:
    $key_912b = { c2 44 [2] e6 4a [2] cd 66 [2] e3 44 [2] f7 5f [2] f8 45 [2] e6 58 [2] e4 59 [2] ff 5f [2] e3 58 [2] ff 77 }

  condition:
    any of them
}