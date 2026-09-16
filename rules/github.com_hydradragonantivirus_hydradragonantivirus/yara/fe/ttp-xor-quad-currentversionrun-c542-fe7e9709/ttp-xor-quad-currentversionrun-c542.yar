rule TTP_XOR_QUAD_CurrentVersionRun_c542 {
  strings:
    $key_c542 = { 96 2d [2] b2 23 [2] 99 0f [2] b7 2d [2] a3 36 [2] ac 2c [2] b2 31 [2] b0 30 [2] ab 36 [2] b7 31 [2] ab 1e }

  condition:
    any of them
}