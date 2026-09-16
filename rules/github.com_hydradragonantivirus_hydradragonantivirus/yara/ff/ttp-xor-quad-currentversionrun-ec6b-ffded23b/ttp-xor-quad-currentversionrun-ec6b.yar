rule TTP_XOR_QUAD_CurrentVersionRun_ec6b {
  strings:
    $key_ec6b = { bf 04 [2] 9b 0a [2] b0 26 [2] 9e 04 [2] 8a 1f [2] 85 05 [2] 9b 18 [2] 99 19 [2] 82 1f [2] 9e 18 [2] 82 37 }

  condition:
    any of them
}