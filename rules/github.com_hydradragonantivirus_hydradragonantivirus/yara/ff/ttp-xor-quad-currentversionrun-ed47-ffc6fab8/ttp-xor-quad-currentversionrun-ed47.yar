rule TTP_XOR_QUAD_CurrentVersionRun_ed47 {
  strings:
    $key_ed47 = { be 28 [2] 9a 26 [2] b1 0a [2] 9f 28 [2] 8b 33 [2] 84 29 [2] 9a 34 [2] 98 35 [2] 83 33 [2] 9f 34 [2] 83 1b }

  condition:
    any of them
}