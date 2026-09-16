rule TTP_XOR_QUAD_CurrentVersionRun_ec4e {
  strings:
    $key_ec4e = { bf 21 [2] 9b 2f [2] b0 03 [2] 9e 21 [2] 8a 3a [2] 85 20 [2] 9b 3d [2] 99 3c [2] 82 3a [2] 9e 3d [2] 82 12 }

  condition:
    any of them
}