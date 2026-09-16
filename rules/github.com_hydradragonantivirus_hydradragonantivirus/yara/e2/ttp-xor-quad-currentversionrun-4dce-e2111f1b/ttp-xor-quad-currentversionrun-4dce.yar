rule TTP_XOR_QUAD_CurrentVersionRun_4dce {
  strings:
    $key_4dce = { 1e a1 [2] 3a af [2] 11 83 [2] 3f a1 [2] 2b ba [2] 24 a0 [2] 3a bd [2] 38 bc [2] 23 ba [2] 3f bd [2] 23 92 }

  condition:
    any of them
}