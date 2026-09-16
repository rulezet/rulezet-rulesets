rule TTP_XOR_QUAD_CurrentVersionRun_ea46 {
  strings:
    $key_ea46 = { b9 29 [2] 9d 27 [2] b6 0b [2] 98 29 [2] 8c 32 [2] 83 28 [2] 9d 35 [2] 9f 34 [2] 84 32 [2] 98 35 [2] 84 1a }

  condition:
    any of them
}