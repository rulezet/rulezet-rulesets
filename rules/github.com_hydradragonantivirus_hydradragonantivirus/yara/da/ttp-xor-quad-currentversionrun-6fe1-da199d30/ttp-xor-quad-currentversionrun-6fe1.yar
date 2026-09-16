rule TTP_XOR_QUAD_CurrentVersionRun_6fe1 {
  strings:
    $key_6fe1 = { 3c 8e [2] 18 80 [2] 33 ac [2] 1d 8e [2] 09 95 [2] 06 8f [2] 18 92 [2] 1a 93 [2] 01 95 [2] 1d 92 [2] 01 bd }

  condition:
    any of them
}