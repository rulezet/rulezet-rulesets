rule TTP_XOR_QUAD_CurrentVersionRun_66ed {
  strings:
    $key_66ed = { 35 82 [2] 11 8c [2] 3a a0 [2] 14 82 [2] 00 99 [2] 0f 83 [2] 11 9e [2] 13 9f [2] 08 99 [2] 14 9e [2] 08 b1 }

  condition:
    any of them
}