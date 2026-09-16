rule TTP_XOR_QUAD_CurrentVersionRun_ea7b {
  strings:
    $key_ea7b = { b9 14 [2] 9d 1a [2] b6 36 [2] 98 14 [2] 8c 0f [2] 83 15 [2] 9d 08 [2] 9f 09 [2] 84 0f [2] 98 08 [2] 84 27 }

  condition:
    any of them
}