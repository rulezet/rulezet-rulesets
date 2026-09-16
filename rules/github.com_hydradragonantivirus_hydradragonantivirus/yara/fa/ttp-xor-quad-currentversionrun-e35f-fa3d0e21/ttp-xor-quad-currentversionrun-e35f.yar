rule TTP_XOR_QUAD_CurrentVersionRun_e35f {
  strings:
    $key_e35f = { b0 30 [2] 94 3e [2] bf 12 [2] 91 30 [2] 85 2b [2] 8a 31 [2] 94 2c [2] 96 2d [2] 8d 2b [2] 91 2c [2] 8d 03 }

  condition:
    any of them
}