rule TTP_XOR_QUAD_CurrentVersionRun_0bed {
  strings:
    $key_0bed = { 58 82 [2] 7c 8c [2] 57 a0 [2] 79 82 [2] 6d 99 [2] 62 83 [2] 7c 9e [2] 7e 9f [2] 65 99 [2] 79 9e [2] 65 b1 }

  condition:
    any of them
}