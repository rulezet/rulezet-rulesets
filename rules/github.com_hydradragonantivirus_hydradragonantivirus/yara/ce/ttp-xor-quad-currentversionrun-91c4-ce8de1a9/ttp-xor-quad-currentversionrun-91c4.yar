rule TTP_XOR_QUAD_CurrentVersionRun_91c4 {
  strings:
    $key_91c4 = { c2 ab [2] e6 a5 [2] cd 89 [2] e3 ab [2] f7 b0 [2] f8 aa [2] e6 b7 [2] e4 b6 [2] ff b0 [2] e3 b7 [2] ff 98 }

  condition:
    any of them
}