rule TTP_XOR_QUAD_CurrentVersionRun_ea7d {
  strings:
    $key_ea7d = { b9 12 [2] 9d 1c [2] b6 30 [2] 98 12 [2] 8c 09 [2] 83 13 [2] 9d 0e [2] 9f 0f [2] 84 09 [2] 98 0e [2] 84 21 }

  condition:
    any of them
}