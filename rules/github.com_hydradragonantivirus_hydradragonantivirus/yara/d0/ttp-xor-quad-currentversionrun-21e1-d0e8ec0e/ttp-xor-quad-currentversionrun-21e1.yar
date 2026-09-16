rule TTP_XOR_QUAD_CurrentVersionRun_21e1 {
  strings:
    $key_21e1 = { 72 8e [2] 56 80 [2] 7d ac [2] 53 8e [2] 47 95 [2] 48 8f [2] 56 92 [2] 54 93 [2] 4f 95 [2] 53 92 [2] 4f bd }

  condition:
    any of them
}