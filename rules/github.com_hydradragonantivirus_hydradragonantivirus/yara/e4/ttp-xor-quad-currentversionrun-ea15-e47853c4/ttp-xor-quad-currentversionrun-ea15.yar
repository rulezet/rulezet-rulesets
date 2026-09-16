rule TTP_XOR_QUAD_CurrentVersionRun_ea15 {
  strings:
    $key_ea15 = { b9 7a [2] 9d 74 [2] b6 58 [2] 98 7a [2] 8c 61 [2] 83 7b [2] 9d 66 [2] 9f 67 [2] 84 61 [2] 98 66 [2] 84 49 }

  condition:
    any of them
}