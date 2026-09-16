rule TTP_XOR_QUAD_CurrentVersionRun_ea6f {
  strings:
    $key_ea6f = { b9 00 [2] 9d 0e [2] b6 22 [2] 98 00 [2] 8c 1b [2] 83 01 [2] 9d 1c [2] 9f 1d [2] 84 1b [2] 98 1c [2] 84 33 }

  condition:
    any of them
}