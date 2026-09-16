rule TTP_XOR_QUAD_CurrentVersionRun_ea14 {
  strings:
    $key_ea14 = { b9 7b [2] 9d 75 [2] b6 59 [2] 98 7b [2] 8c 60 [2] 83 7a [2] 9d 67 [2] 9f 66 [2] 84 60 [2] 98 67 [2] 84 48 }

  condition:
    any of them
}