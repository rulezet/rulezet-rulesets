rule TTP_XOR_QUAD_CurrentVersionRun_25fd {
  strings:
    $key_25fd = { 76 92 [2] 52 9c [2] 79 b0 [2] 57 92 [2] 43 89 [2] 4c 93 [2] 52 8e [2] 50 8f [2] 4b 89 [2] 57 8e [2] 4b a1 }

  condition:
    any of them
}