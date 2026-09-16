rule TTP_XOR_QUAD_CurrentVersionRun_c327 {
  strings:
    $key_c327 = { 90 48 [2] b4 46 [2] 9f 6a [2] b1 48 [2] a5 53 [2] aa 49 [2] b4 54 [2] b6 55 [2] ad 53 [2] b1 54 [2] ad 7b }

  condition:
    any of them
}