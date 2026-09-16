rule TTP_XOR_QUAD_CurrentVersionRun_bb42 {
  strings:
    $key_bb42 = { e8 2d [2] cc 23 [2] e7 0f [2] c9 2d [2] dd 36 [2] d2 2c [2] cc 31 [2] ce 30 [2] d5 36 [2] c9 31 [2] d5 1e }

  condition:
    any of them
}