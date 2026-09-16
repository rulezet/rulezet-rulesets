rule TTP_XOR_QUAD_CurrentVersionRun_35e1 {
  strings:
    $key_35e1 = { 66 8e [2] 42 80 [2] 69 ac [2] 47 8e [2] 53 95 [2] 5c 8f [2] 42 92 [2] 40 93 [2] 5b 95 [2] 47 92 [2] 5b bd }

  condition:
    any of them
}