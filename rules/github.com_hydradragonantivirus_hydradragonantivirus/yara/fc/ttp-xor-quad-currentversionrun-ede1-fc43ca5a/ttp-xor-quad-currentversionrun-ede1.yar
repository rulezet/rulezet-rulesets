rule TTP_XOR_QUAD_CurrentVersionRun_ede1 {
  strings:
    $key_ede1 = { be 8e [2] 9a 80 [2] b1 ac [2] 9f 8e [2] 8b 95 [2] 84 8f [2] 9a 92 [2] 98 93 [2] 83 95 [2] 9f 92 [2] 83 bd }

  condition:
    any of them
}