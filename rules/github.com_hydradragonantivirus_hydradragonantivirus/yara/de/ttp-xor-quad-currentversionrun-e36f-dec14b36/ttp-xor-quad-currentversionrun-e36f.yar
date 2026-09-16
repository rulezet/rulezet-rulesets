rule TTP_XOR_QUAD_CurrentVersionRun_e36f {
  strings:
    $key_e36f = { b0 00 [2] 94 0e [2] bf 22 [2] 91 00 [2] 85 1b [2] 8a 01 [2] 94 1c [2] 96 1d [2] 8d 1b [2] 91 1c [2] 8d 33 }

  condition:
    any of them
}