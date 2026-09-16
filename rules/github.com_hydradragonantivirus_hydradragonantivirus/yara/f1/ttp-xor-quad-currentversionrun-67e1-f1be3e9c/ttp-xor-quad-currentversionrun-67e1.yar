rule TTP_XOR_QUAD_CurrentVersionRun_67e1 {
  strings:
    $key_67e1 = { 34 8e [2] 10 80 [2] 3b ac [2] 15 8e [2] 01 95 [2] 0e 8f [2] 10 92 [2] 12 93 [2] 09 95 [2] 15 92 [2] 09 bd }

  condition:
    any of them
}