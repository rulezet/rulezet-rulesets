rule TTP_XOR_QUAD_CurrentVersionRun_c311 {
  strings:
    $key_c311 = { 90 7e [2] b4 70 [2] 9f 5c [2] b1 7e [2] a5 65 [2] aa 7f [2] b4 62 [2] b6 63 [2] ad 65 [2] b1 62 [2] ad 4d }

  condition:
    any of them
}