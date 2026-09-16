rule TTP_XOR_QUAD_CurrentVersionRun_ea47 {
  strings:
    $key_ea47 = { b9 28 [2] 9d 26 [2] b6 0a [2] 98 28 [2] 8c 33 [2] 83 29 [2] 9d 34 [2] 9f 35 [2] 84 33 [2] 98 34 [2] 84 1b }

  condition:
    any of them
}