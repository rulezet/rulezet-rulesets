rule TTP_XOR_QUAD_CurrentVersionRun_ed5b {
  strings:
    $key_ed5b = { be 34 [2] 9a 3a [2] b1 16 [2] 9f 34 [2] 8b 2f [2] 84 35 [2] 9a 28 [2] 98 29 [2] 83 2f [2] 9f 28 [2] 83 07 }

  condition:
    any of them
}