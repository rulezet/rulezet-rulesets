rule TTP_XOR_QUAD_CurrentVersionRun_ea09 {
  strings:
    $key_ea09 = { b9 66 [2] 9d 68 [2] b6 44 [2] 98 66 [2] 8c 7d [2] 83 67 [2] 9d 7a [2] 9f 7b [2] 84 7d [2] 98 7a [2] 84 55 }

  condition:
    any of them
}