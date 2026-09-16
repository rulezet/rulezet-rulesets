rule TTP_XOR_QUAD_CurrentVersionRun_c47b {
  strings:
    $key_c47b = { 97 14 [2] b3 1a [2] 98 36 [2] b6 14 [2] a2 0f [2] ad 15 [2] b3 08 [2] b1 09 [2] aa 0f [2] b6 08 [2] aa 27 }

  condition:
    any of them
}