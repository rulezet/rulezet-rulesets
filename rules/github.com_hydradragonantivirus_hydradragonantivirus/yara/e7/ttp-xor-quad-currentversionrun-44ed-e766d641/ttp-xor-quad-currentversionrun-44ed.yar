rule TTP_XOR_QUAD_CurrentVersionRun_44ed {
  strings:
    $key_44ed = { 17 82 [2] 33 8c [2] 18 a0 [2] 36 82 [2] 22 99 [2] 2d 83 [2] 33 9e [2] 31 9f [2] 2a 99 [2] 36 9e [2] 2a b1 }

  condition:
    any of them
}