rule TTP_XOR_QUAD_CurrentVersionRun_50e1 {
  strings:
    $key_50e1 = { 03 8e [2] 27 80 [2] 0c ac [2] 22 8e [2] 36 95 [2] 39 8f [2] 27 92 [2] 25 93 [2] 3e 95 [2] 22 92 [2] 3e bd }

  condition:
    any of them
}