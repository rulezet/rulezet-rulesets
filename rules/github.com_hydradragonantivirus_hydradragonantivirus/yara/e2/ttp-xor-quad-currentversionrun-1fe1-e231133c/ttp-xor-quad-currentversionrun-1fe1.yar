rule TTP_XOR_QUAD_CurrentVersionRun_1fe1 {
  strings:
    $key_1fe1 = { 4c 8e [2] 68 80 [2] 43 ac [2] 6d 8e [2] 79 95 [2] 76 8f [2] 68 92 [2] 6a 93 [2] 71 95 [2] 6d 92 [2] 71 bd }

  condition:
    any of them
}