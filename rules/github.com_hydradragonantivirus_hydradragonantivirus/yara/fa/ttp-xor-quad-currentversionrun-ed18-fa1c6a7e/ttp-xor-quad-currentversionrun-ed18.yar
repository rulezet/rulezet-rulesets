rule TTP_XOR_QUAD_CurrentVersionRun_ed18 {
  strings:
    $key_ed18 = { be 77 [2] 9a 79 [2] b1 55 [2] 9f 77 [2] 8b 6c [2] 84 76 [2] 9a 6b [2] 98 6a [2] 83 6c [2] 9f 6b [2] 83 44 }

  condition:
    any of them
}