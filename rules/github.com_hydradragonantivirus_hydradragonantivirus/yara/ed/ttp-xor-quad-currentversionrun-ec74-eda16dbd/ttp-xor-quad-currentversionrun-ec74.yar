rule TTP_XOR_QUAD_CurrentVersionRun_ec74 {
  strings:
    $key_ec74 = { bf 1b [2] 9b 15 [2] b0 39 [2] 9e 1b [2] 8a 00 [2] 85 1a [2] 9b 07 [2] 99 06 [2] 82 00 [2] 9e 07 [2] 82 28 }

  condition:
    any of them
}