rule TTP_XOR_QUAD_CurrentVersionRun_e642 {
  strings:
    $key_e642 = { b5 2d [2] 91 23 [2] ba 0f [2] 94 2d [2] 80 36 [2] 8f 2c [2] 91 31 [2] 93 30 [2] 88 36 [2] 94 31 [2] 88 1e }

  condition:
    any of them
}