rule TTP_XOR_QUAD_CurrentVersionRun_c46b {
  strings:
    $key_c46b = { 97 04 [2] b3 0a [2] 98 26 [2] b6 04 [2] a2 1f [2] ad 05 [2] b3 18 [2] b1 19 [2] aa 1f [2] b6 18 [2] aa 37 }

  condition:
    any of them
}