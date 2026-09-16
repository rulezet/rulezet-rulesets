rule TTP_XOR_QUAD_CurrentVersionRun_ed04 {
  strings:
    $key_ed04 = { be 6b [2] 9a 65 [2] b1 49 [2] 9f 6b [2] 8b 70 [2] 84 6a [2] 9a 77 [2] 98 76 [2] 83 70 [2] 9f 77 [2] 83 58 }

  condition:
    any of them
}