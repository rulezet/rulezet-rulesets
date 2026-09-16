rule TTP_XOR_QUAD_CurrentVersionRun_ea78 {
  strings:
    $key_ea78 = { b9 17 [2] 9d 19 [2] b6 35 [2] 98 17 [2] 8c 0c [2] 83 16 [2] 9d 0b [2] 9f 0a [2] 84 0c [2] 98 0b [2] 84 24 }

  condition:
    any of them
}