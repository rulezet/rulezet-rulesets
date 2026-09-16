rule TTP_XOR_QUAD_CurrentVersionRun_5bed {
  strings:
    $key_5bed = { 08 82 [2] 2c 8c [2] 07 a0 [2] 29 82 [2] 3d 99 [2] 32 83 [2] 2c 9e [2] 2e 9f [2] 35 99 [2] 29 9e [2] 35 b1 }

  condition:
    any of them
}