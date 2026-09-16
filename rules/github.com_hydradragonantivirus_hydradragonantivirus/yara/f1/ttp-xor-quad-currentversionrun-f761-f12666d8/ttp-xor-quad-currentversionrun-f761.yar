rule TTP_XOR_QUAD_CurrentVersionRun_f761 {
  strings:
    $key_f761 = { a4 0e [2] 80 00 [2] ab 2c [2] 85 0e [2] 91 15 [2] 9e 0f [2] 80 12 [2] 82 13 [2] 99 15 [2] 85 12 [2] 99 3d }

  condition:
    any of them
}