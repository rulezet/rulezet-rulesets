rule TTP_XOR_QUAD_CurrentVersionRun_26ed {
  strings:
    $key_26ed = { 75 82 [2] 51 8c [2] 7a a0 [2] 54 82 [2] 40 99 [2] 4f 83 [2] 51 9e [2] 53 9f [2] 48 99 [2] 54 9e [2] 48 b1 }

  condition:
    any of them
}