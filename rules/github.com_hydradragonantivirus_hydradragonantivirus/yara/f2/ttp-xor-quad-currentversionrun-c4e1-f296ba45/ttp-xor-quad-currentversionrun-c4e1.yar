rule TTP_XOR_QUAD_CurrentVersionRun_c4e1 {
  strings:
    $key_c4e1 = { 97 8e [2] b3 80 [2] 98 ac [2] b6 8e [2] a2 95 [2] ad 8f [2] b3 92 [2] b1 93 [2] aa 95 [2] b6 92 [2] aa bd }

  condition:
    any of them
}