rule TTP_XOR_QUAD_CurrentVersionRun_3743 {
  strings:
    $key_3743 = { 64 2c [2] 40 22 [2] 6b 0e [2] 45 2c [2] 51 37 [2] 5e 2d [2] 40 30 [2] 42 31 [2] 59 37 [2] 45 30 [2] 59 1f }

  condition:
    any of them
}