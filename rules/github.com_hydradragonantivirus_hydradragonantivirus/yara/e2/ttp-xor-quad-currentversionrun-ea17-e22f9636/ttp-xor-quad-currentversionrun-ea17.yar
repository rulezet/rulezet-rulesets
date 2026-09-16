rule TTP_XOR_QUAD_CurrentVersionRun_ea17 {
  strings:
    $key_ea17 = { b9 78 [2] 9d 76 [2] b6 5a [2] 98 78 [2] 8c 63 [2] 83 79 [2] 9d 64 [2] 9f 65 [2] 84 63 [2] 98 64 [2] 84 4b }

  condition:
    any of them
}