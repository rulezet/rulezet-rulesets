rule TTP_XOR_QUAD_CurrentVersionRun_ec5f {
  strings:
    $key_ec5f = { bf 30 [2] 9b 3e [2] b0 12 [2] 9e 30 [2] 8a 2b [2] 85 31 [2] 9b 2c [2] 99 2d [2] 82 2b [2] 9e 2c [2] 82 03 }

  condition:
    any of them
}