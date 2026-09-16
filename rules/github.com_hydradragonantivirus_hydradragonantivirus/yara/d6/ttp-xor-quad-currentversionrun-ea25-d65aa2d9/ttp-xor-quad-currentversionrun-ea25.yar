rule TTP_XOR_QUAD_CurrentVersionRun_ea25 {
  strings:
    $key_ea25 = { b9 4a [2] 9d 44 [2] b6 68 [2] 98 4a [2] 8c 51 [2] 83 4b [2] 9d 56 [2] 9f 57 [2] 84 51 [2] 98 56 [2] 84 79 }

  condition:
    any of them
}