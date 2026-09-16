rule TTP_XOR_QUAD_CurrentVersionRun_16e1 {
  strings:
    $key_16e1 = { 45 8e [2] 61 80 [2] 4a ac [2] 64 8e [2] 70 95 [2] 7f 8f [2] 61 92 [2] 63 93 [2] 78 95 [2] 64 92 [2] 78 bd }

  condition:
    any of them
}