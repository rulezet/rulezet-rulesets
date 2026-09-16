rule TTP_XOR_QUAD_CurrentVersionRun_ec1b {
  strings:
    $key_ec1b = { bf 74 [2] 9b 7a [2] b0 56 [2] 9e 74 [2] 8a 6f [2] 85 75 [2] 9b 68 [2] 99 69 [2] 82 6f [2] 9e 68 [2] 82 47 }

  condition:
    any of them
}