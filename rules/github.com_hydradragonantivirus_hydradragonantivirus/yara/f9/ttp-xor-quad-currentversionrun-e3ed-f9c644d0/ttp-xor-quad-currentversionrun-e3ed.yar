rule TTP_XOR_QUAD_CurrentVersionRun_e3ed {
  strings:
    $key_e3ed = { b0 82 [2] 94 8c [2] bf a0 [2] 91 82 [2] 85 99 [2] 8a 83 [2] 94 9e [2] 96 9f [2] 8d 99 [2] 91 9e [2] 8d b1 }

  condition:
    any of them
}