rule TTP_XOR_QUAD_CurrentVersionRun_ece9 {
  strings:
    $key_ece9 = { bf 86 [2] 9b 88 [2] b0 a4 [2] 9e 86 [2] 8a 9d [2] 85 87 [2] 9b 9a [2] 99 9b [2] 82 9d [2] 9e 9a [2] 82 b5 }

  condition:
    any of them
}