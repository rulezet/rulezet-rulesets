rule TTP_XOR_QUAD_CurrentVersionRun_ec0b {
  strings:
    $key_ec0b = { bf 64 [2] 9b 6a [2] b0 46 [2] 9e 64 [2] 8a 7f [2] 85 65 [2] 9b 78 [2] 99 79 [2] 82 7f [2] 9e 78 [2] 82 57 }

  condition:
    any of them
}