rule TTP_XOR_QUAD_CurrentVersionRun_ec4b {
  strings:
    $key_ec4b = { bf 24 [2] 9b 2a [2] b0 06 [2] 9e 24 [2] 8a 3f [2] 85 25 [2] 9b 38 [2] 99 39 [2] 82 3f [2] 9e 38 [2] 82 17 }

  condition:
    any of them
}