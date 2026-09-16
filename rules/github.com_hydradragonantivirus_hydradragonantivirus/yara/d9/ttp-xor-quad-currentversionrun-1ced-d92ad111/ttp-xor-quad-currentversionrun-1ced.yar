rule TTP_XOR_QUAD_CurrentVersionRun_1ced {
  strings:
    $key_1ced = { 4f 82 [2] 6b 8c [2] 40 a0 [2] 6e 82 [2] 7a 99 [2] 75 83 [2] 6b 9e [2] 69 9f [2] 72 99 [2] 6e 9e [2] 72 b1 }

  condition:
    any of them
}