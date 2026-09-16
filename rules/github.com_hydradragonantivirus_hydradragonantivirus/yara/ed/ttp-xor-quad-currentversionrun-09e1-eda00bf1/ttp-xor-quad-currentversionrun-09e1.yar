rule TTP_XOR_QUAD_CurrentVersionRun_09e1 {
  strings:
    $key_09e1 = { 5a 8e [2] 7e 80 [2] 55 ac [2] 7b 8e [2] 6f 95 [2] 60 8f [2] 7e 92 [2] 7c 93 [2] 67 95 [2] 7b 92 [2] 67 bd }

  condition:
    any of them
}