rule TTP_XOR_QUAD_CurrentVersionRun_76ed {
  strings:
    $key_76ed = { 25 82 [2] 01 8c [2] 2a a0 [2] 04 82 [2] 10 99 [2] 1f 83 [2] 01 9e [2] 03 9f [2] 18 99 [2] 04 9e [2] 18 b1 }

  condition:
    any of them
}