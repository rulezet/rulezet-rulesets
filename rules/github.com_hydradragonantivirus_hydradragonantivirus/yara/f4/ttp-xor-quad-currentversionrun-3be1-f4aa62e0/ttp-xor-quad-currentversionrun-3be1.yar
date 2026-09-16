rule TTP_XOR_QUAD_CurrentVersionRun_3be1 {
  strings:
    $key_3be1 = { 68 8e [2] 4c 80 [2] 67 ac [2] 49 8e [2] 5d 95 [2] 52 8f [2] 4c 92 [2] 4e 93 [2] 55 95 [2] 49 92 [2] 55 bd }

  condition:
    any of them
}