rule TTP_XOR_QUAD_CurrentVersionRun_ece1 {
  strings:
    $key_ece1 = { bf 8e [2] 9b 80 [2] b0 ac [2] 9e 8e [2] 8a 95 [2] 85 8f [2] 9b 92 [2] 99 93 [2] 82 95 [2] 9e 92 [2] 82 bd }

  condition:
    any of them
}