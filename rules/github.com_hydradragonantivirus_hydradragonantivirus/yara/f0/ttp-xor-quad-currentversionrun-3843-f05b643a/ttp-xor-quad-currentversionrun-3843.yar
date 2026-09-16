rule TTP_XOR_QUAD_CurrentVersionRun_3843 {
  strings:
    $key_3843 = { 6b 2c [2] 4f 22 [2] 64 0e [2] 4a 2c [2] 5e 37 [2] 51 2d [2] 4f 30 [2] 4d 31 [2] 56 37 [2] 4a 30 [2] 56 1f }

  condition:
    any of them
}