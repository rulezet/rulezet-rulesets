rule TTP_XOR_QUAD_CurrentVersionRun_ed38 {
  strings:
    $key_ed38 = { be 57 [2] 9a 59 [2] b1 75 [2] 9f 57 [2] 8b 4c [2] 84 56 [2] 9a 4b [2] 98 4a [2] 83 4c [2] 9f 4b [2] 83 64 }

  condition:
    any of them
}