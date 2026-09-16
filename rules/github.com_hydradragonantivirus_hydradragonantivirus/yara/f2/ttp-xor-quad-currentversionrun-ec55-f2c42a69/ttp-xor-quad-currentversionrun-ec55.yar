rule TTP_XOR_QUAD_CurrentVersionRun_ec55 {
  strings:
    $key_ec55 = { bf 3a [2] 9b 34 [2] b0 18 [2] 9e 3a [2] 8a 21 [2] 85 3b [2] 9b 26 [2] 99 27 [2] 82 21 [2] 9e 26 [2] 82 09 }

  condition:
    any of them
}