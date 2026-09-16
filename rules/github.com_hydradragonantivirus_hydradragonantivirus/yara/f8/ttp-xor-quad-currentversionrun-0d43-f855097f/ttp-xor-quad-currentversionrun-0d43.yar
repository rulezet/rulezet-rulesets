rule TTP_XOR_QUAD_CurrentVersionRun_0d43 {
  strings:
    $key_0d43 = { 5e 2c [2] 7a 22 [2] 51 0e [2] 7f 2c [2] 6b 37 [2] 64 2d [2] 7a 30 [2] 78 31 [2] 63 37 [2] 7f 30 [2] 63 1f }

  condition:
    any of them
}