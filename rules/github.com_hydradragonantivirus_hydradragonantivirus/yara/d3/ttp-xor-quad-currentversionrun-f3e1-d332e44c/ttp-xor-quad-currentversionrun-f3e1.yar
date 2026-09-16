rule TTP_XOR_QUAD_CurrentVersionRun_f3e1 {
  strings:
    $key_f3e1 = { a0 8e [2] 84 80 [2] af ac [2] 81 8e [2] 95 95 [2] 9a 8f [2] 84 92 [2] 86 93 [2] 9d 95 [2] 81 92 [2] 9d bd }

  condition:
    any of them
}