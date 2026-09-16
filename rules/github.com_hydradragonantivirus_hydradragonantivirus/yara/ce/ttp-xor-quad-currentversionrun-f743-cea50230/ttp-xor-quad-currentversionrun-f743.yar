rule TTP_XOR_QUAD_CurrentVersionRun_f743 {
  strings:
    $key_f743 = { a4 2c [2] 80 22 [2] ab 0e [2] 85 2c [2] 91 37 [2] 9e 2d [2] 80 30 [2] 82 31 [2] 99 37 [2] 85 30 [2] 99 1f }

  condition:
    any of them
}