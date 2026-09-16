rule TTP_XOR_QUAD_CurrentVersionRun_52fd {
  strings:
    $key_52fd = { 01 92 [2] 25 9c [2] 0e b0 [2] 20 92 [2] 34 89 [2] 3b 93 [2] 25 8e [2] 27 8f [2] 3c 89 [2] 20 8e [2] 3c a1 }

  condition:
    any of them
}