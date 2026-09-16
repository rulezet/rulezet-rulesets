rule TTP_XOR_QUAD_CurrentVersionRun_ec5e {
  strings:
    $key_ec5e = { bf 31 [2] 9b 3f [2] b0 13 [2] 9e 31 [2] 8a 2a [2] 85 30 [2] 9b 2d [2] 99 2c [2] 82 2a [2] 9e 2d [2] 82 02 }

  condition:
    any of them
}