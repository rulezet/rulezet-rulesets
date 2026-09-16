rule TTP_XOR_QUAD_CurrentVersionRun_fde1 {
  strings:
    $key_fde1 = { ae 8e [2] 8a 80 [2] a1 ac [2] 8f 8e [2] 9b 95 [2] 94 8f [2] 8a 92 [2] 88 93 [2] 93 95 [2] 8f 92 [2] 93 bd }

  condition:
    any of them
}