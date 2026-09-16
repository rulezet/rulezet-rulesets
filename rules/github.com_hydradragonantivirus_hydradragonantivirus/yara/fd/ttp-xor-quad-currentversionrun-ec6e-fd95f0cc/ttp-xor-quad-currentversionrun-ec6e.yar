rule TTP_XOR_QUAD_CurrentVersionRun_ec6e {
  strings:
    $key_ec6e = { bf 01 [2] 9b 0f [2] b0 23 [2] 9e 01 [2] 8a 1a [2] 85 00 [2] 9b 1d [2] 99 1c [2] 82 1a [2] 9e 1d [2] 82 32 }

  condition:
    any of them
}