rule TTP_XOR_QUAD_CurrentVersionRun_4be1 {
  strings:
    $key_4be1 = { 18 8e [2] 3c 80 [2] 17 ac [2] 39 8e [2] 2d 95 [2] 22 8f [2] 3c 92 [2] 3e 93 [2] 25 95 [2] 39 92 [2] 25 bd }

  condition:
    any of them
}