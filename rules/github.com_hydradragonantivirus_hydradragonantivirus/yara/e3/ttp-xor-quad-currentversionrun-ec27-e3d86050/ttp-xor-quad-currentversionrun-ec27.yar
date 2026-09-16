rule TTP_XOR_QUAD_CurrentVersionRun_ec27 {
  strings:
    $key_ec27 = { bf 48 [2] 9b 46 [2] b0 6a [2] 9e 48 [2] 8a 53 [2] 85 49 [2] 9b 54 [2] 99 55 [2] 82 53 [2] 9e 54 [2] 82 7b }

  condition:
    any of them
}