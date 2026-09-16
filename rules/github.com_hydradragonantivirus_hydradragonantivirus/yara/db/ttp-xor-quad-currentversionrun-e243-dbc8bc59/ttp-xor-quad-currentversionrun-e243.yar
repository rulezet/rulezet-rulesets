rule TTP_XOR_QUAD_CurrentVersionRun_e243 {
  strings:
    $key_e243 = { b1 2c [2] 95 22 [2] be 0e [2] 90 2c [2] 84 37 [2] 8b 2d [2] 95 30 [2] 97 31 [2] 8c 37 [2] 90 30 [2] 8c 1f }

  condition:
    any of them
}