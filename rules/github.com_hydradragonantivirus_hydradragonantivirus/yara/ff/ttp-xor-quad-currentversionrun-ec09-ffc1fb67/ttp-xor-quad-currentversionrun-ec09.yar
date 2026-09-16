rule TTP_XOR_QUAD_CurrentVersionRun_ec09 {
  strings:
    $key_ec09 = { bf 66 [2] 9b 68 [2] b0 44 [2] 9e 66 [2] 8a 7d [2] 85 67 [2] 9b 7a [2] 99 7b [2] 82 7d [2] 9e 7a [2] 82 55 }

  condition:
    any of them
}