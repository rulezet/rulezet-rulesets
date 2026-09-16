rule TTP_XOR_QUAD_CurrentVersionRun_ea4b {
  strings:
    $key_ea4b = { b9 24 [2] 9d 2a [2] b6 06 [2] 98 24 [2] 8c 3f [2] 83 25 [2] 9d 38 [2] 9f 39 [2] 84 3f [2] 98 38 [2] 84 17 }

  condition:
    any of them
}