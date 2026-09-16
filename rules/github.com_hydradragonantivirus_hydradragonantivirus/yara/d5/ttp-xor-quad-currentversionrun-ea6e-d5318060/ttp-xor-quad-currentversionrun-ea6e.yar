rule TTP_XOR_QUAD_CurrentVersionRun_ea6e {
  strings:
    $key_ea6e = { b9 01 [2] 9d 0f [2] b6 23 [2] 98 01 [2] 8c 1a [2] 83 00 [2] 9d 1d [2] 9f 1c [2] 84 1a [2] 98 1d [2] 84 32 }

  condition:
    any of them
}