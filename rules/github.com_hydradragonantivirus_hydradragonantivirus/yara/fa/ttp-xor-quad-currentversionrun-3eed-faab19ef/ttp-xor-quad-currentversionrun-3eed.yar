rule TTP_XOR_QUAD_CurrentVersionRun_3eed {
  strings:
    $key_3eed = { 6d 82 [2] 49 8c [2] 62 a0 [2] 4c 82 [2] 58 99 [2] 57 83 [2] 49 9e [2] 4b 9f [2] 50 99 [2] 4c 9e [2] 50 b1 }

  condition:
    any of them
}