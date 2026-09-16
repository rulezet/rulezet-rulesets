rule TTP_XOR_QUAD_CurrentVersionRun_ed78 {
  strings:
    $key_ed78 = { be 17 [2] 9a 19 [2] b1 35 [2] 9f 17 [2] 8b 0c [2] 84 16 [2] 9a 0b [2] 98 0a [2] 83 0c [2] 9f 0b [2] 83 24 }

  condition:
    any of them
}