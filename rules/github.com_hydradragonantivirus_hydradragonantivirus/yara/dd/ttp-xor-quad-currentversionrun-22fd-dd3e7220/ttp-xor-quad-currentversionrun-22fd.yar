rule TTP_XOR_QUAD_CurrentVersionRun_22fd {
  strings:
    $key_22fd = { 71 92 [2] 55 9c [2] 7e b0 [2] 50 92 [2] 44 89 [2] 4b 93 [2] 55 8e [2] 57 8f [2] 4c 89 [2] 50 8e [2] 4c a1 }

  condition:
    any of them
}