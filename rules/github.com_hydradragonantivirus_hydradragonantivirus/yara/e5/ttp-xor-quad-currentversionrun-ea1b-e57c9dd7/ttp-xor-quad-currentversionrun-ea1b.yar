rule TTP_XOR_QUAD_CurrentVersionRun_ea1b {
  strings:
    $key_ea1b = { b9 74 [2] 9d 7a [2] b6 56 [2] 98 74 [2] 8c 6f [2] 83 75 [2] 9d 68 [2] 9f 69 [2] 84 6f [2] 98 68 [2] 84 47 }

  condition:
    any of them
}