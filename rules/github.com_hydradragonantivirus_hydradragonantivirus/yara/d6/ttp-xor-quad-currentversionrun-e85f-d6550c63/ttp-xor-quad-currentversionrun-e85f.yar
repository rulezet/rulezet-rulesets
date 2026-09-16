rule TTP_XOR_QUAD_CurrentVersionRun_e85f {
  strings:
    $key_e85f = { bb 30 [2] 9f 3e [2] b4 12 [2] 9a 30 [2] 8e 2b [2] 81 31 [2] 9f 2c [2] 9d 2d [2] 86 2b [2] 9a 2c [2] 86 03 }

  condition:
    any of them
}