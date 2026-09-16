rule TTP_XOR_QUAD_CurrentVersionRun_29e1 {
  strings:
    $key_29e1 = { 7a 8e [2] 5e 80 [2] 75 ac [2] 5b 8e [2] 4f 95 [2] 40 8f [2] 5e 92 [2] 5c 93 [2] 47 95 [2] 5b 92 [2] 47 bd }

  condition:
    any of them
}