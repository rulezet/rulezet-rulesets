rule TTP_XOR_QUAD_CurrentVersionRun_3ae1 {
  strings:
    $key_3ae1 = { 69 8e [2] 4d 80 [2] 66 ac [2] 48 8e [2] 5c 95 [2] 53 8f [2] 4d 92 [2] 4f 93 [2] 54 95 [2] 48 92 [2] 54 bd }

  condition:
    any of them
}