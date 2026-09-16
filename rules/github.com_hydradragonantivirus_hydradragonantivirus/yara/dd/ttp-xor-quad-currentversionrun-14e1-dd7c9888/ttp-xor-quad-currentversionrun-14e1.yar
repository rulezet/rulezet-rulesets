rule TTP_XOR_QUAD_CurrentVersionRun_14e1 {
  strings:
    $key_14e1 = { 47 8e [2] 63 80 [2] 48 ac [2] 66 8e [2] 72 95 [2] 7d 8f [2] 63 92 [2] 61 93 [2] 7a 95 [2] 66 92 [2] 7a bd }

  condition:
    any of them
}