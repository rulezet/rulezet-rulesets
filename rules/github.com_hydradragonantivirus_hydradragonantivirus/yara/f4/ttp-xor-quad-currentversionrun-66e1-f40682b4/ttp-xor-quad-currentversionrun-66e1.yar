rule TTP_XOR_QUAD_CurrentVersionRun_66e1 {
  strings:
    $key_66e1 = { 35 8e [2] 11 80 [2] 3a ac [2] 14 8e [2] 00 95 [2] 0f 8f [2] 11 92 [2] 13 93 [2] 08 95 [2] 14 92 [2] 08 bd }

  condition:
    any of them
}