rule TTP_XOR_QUAD_CurrentVersionRun_ec47 {
  strings:
    $key_ec47 = { bf 28 [2] 9b 26 [2] b0 0a [2] 9e 28 [2] 8a 33 [2] 85 29 [2] 9b 34 [2] 99 35 [2] 82 33 [2] 9e 34 [2] 82 1b }

  condition:
    any of them
}