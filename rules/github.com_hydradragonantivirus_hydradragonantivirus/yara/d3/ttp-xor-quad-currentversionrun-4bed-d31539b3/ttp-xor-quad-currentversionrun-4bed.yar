rule TTP_XOR_QUAD_CurrentVersionRun_4bed {
  strings:
    $key_4bed = { 18 82 [2] 3c 8c [2] 17 a0 [2] 39 82 [2] 2d 99 [2] 22 83 [2] 3c 9e [2] 3e 9f [2] 25 99 [2] 39 9e [2] 25 b1 }

  condition:
    any of them
}