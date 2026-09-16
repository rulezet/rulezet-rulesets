rule TTP_XOR_QUAD_CurrentVersionRun_7ded {
  strings:
    $key_7ded = { 2e 82 [2] 0a 8c [2] 21 a0 [2] 0f 82 [2] 1b 99 [2] 14 83 [2] 0a 9e [2] 08 9f [2] 13 99 [2] 0f 9e [2] 13 b1 }

  condition:
    any of them
}