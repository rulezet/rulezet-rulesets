rule TTP_XOR_QUAD_CurrentVersionRun_0be1 {
  strings:
    $key_0be1 = { 58 8e [2] 7c 80 [2] 57 ac [2] 79 8e [2] 6d 95 [2] 62 8f [2] 7c 92 [2] 7e 93 [2] 65 95 [2] 79 92 [2] 65 bd }

  condition:
    any of them
}