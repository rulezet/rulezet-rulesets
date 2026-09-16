rule TTP_XOR_QUAD_CurrentVersionRun_ec72 {
  strings:
    $key_ec72 = { bf 1d [2] 9b 13 [2] b0 3f [2] 9e 1d [2] 8a 06 [2] 85 1c [2] 9b 01 [2] 99 00 [2] 82 06 [2] 9e 01 [2] 82 2e }

  condition:
    any of them
}