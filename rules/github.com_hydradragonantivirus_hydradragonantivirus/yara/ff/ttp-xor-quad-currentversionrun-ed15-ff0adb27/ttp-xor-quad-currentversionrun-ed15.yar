rule TTP_XOR_QUAD_CurrentVersionRun_ed15 {
  strings:
    $key_ed15 = { be 7a [2] 9a 74 [2] b1 58 [2] 9f 7a [2] 8b 61 [2] 84 7b [2] 9a 66 [2] 98 67 [2] 83 61 [2] 9f 66 [2] 83 49 }

  condition:
    any of them
}