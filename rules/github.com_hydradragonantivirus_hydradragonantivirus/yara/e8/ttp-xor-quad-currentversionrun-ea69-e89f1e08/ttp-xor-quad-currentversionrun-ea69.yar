rule TTP_XOR_QUAD_CurrentVersionRun_ea69 {
  strings:
    $key_ea69 = { b9 06 [2] 9d 08 [2] b6 24 [2] 98 06 [2] 8c 1d [2] 83 07 [2] 9d 1a [2] 9f 1b [2] 84 1d [2] 98 1a [2] 84 35 }

  condition:
    any of them
}