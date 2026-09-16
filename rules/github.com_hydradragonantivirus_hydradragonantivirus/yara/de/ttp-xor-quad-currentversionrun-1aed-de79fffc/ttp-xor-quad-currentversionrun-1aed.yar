rule TTP_XOR_QUAD_CurrentVersionRun_1aed {
  strings:
    $key_1aed = { 49 82 [2] 6d 8c [2] 46 a0 [2] 68 82 [2] 7c 99 [2] 73 83 [2] 6d 9e [2] 6f 9f [2] 74 99 [2] 68 9e [2] 74 b1 }

  condition:
    any of them
}