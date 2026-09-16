rule TTP_XOR_QUAD_CurrentVersionRun_ea6a {
  strings:
    $key_ea6a = { b9 05 [2] 9d 0b [2] b6 27 [2] 98 05 [2] 8c 1e [2] 83 04 [2] 9d 19 [2] 9f 18 [2] 84 1e [2] 98 19 [2] 84 36 }

  condition:
    any of them
}