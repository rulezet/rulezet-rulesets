rule TTP_XOR_QUAD_CurrentVersionRun_39e1 {
  strings:
    $key_39e1 = { 6a 8e [2] 4e 80 [2] 65 ac [2] 4b 8e [2] 5f 95 [2] 50 8f [2] 4e 92 [2] 4c 93 [2] 57 95 [2] 4b 92 [2] 57 bd }

  condition:
    any of them
}