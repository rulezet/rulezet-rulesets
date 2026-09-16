rule TTP_XOR_QUAD_CurrentVersionRun_91b7 {
  strings:
    $key_91b7 = { c2 d8 [2] e6 d6 [2] cd fa [2] e3 d8 [2] f7 c3 [2] f8 d9 [2] e6 c4 [2] e4 c5 [2] ff c3 [2] e3 c4 [2] ff eb }

  condition:
    any of them
}