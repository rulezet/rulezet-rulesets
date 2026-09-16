rule TTP_XOR_QUAD_CurrentVersionRun_48e1 {
  strings:
    $key_48e1 = { 1b 8e [2] 3f 80 [2] 14 ac [2] 3a 8e [2] 2e 95 [2] 21 8f [2] 3f 92 [2] 3d 93 [2] 26 95 [2] 3a 92 [2] 26 bd }

  condition:
    any of them
}