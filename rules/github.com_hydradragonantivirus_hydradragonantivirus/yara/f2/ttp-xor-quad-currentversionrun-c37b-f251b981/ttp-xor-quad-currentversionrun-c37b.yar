rule TTP_XOR_QUAD_CurrentVersionRun_c37b {
  strings:
    $key_c37b = { 90 14 [2] b4 1a [2] 9f 36 [2] b1 14 [2] a5 0f [2] aa 15 [2] b4 08 [2] b6 09 [2] ad 0f [2] b1 08 [2] ad 27 }

  condition:
    any of them
}