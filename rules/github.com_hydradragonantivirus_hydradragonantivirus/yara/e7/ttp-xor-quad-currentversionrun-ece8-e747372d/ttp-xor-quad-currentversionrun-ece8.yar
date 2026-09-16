rule TTP_XOR_QUAD_CurrentVersionRun_ece8 {
  strings:
    $key_ece8 = { bf 87 [2] 9b 89 [2] b0 a5 [2] 9e 87 [2] 8a 9c [2] 85 86 [2] 9b 9b [2] 99 9a [2] 82 9c [2] 9e 9b [2] 82 b4 }

  condition:
    any of them
}