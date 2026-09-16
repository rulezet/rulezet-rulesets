rule TTP_XOR_QUAD_CurrentVersionRun_42e1 {
  strings:
    $key_42e1 = { 11 8e [2] 35 80 [2] 1e ac [2] 30 8e [2] 24 95 [2] 2b 8f [2] 35 92 [2] 37 93 [2] 2c 95 [2] 30 92 [2] 2c bd }

  condition:
    any of them
}