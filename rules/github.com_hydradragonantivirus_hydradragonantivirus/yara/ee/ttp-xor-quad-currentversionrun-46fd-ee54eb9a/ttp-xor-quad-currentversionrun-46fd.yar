rule TTP_XOR_QUAD_CurrentVersionRun_46fd {
  strings:
    $key_46fd = { 15 92 [2] 31 9c [2] 1a b0 [2] 34 92 [2] 20 89 [2] 2f 93 [2] 31 8e [2] 33 8f [2] 28 89 [2] 34 8e [2] 28 a1 }

  condition:
    any of them
}