rule TTP_XOR_QUAD_CurrentVersionRun_07fd {
  strings:
    $key_07fd = { 54 92 [2] 70 9c [2] 5b b0 [2] 75 92 [2] 61 89 [2] 6e 93 [2] 70 8e [2] 72 8f [2] 69 89 [2] 75 8e [2] 69 a1 }

  condition:
    any of them
}