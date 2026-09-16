rule TTP_XOR_QUAD_CurrentVersionRun_24fd {
  strings:
    $key_24fd = { 77 92 [2] 53 9c [2] 78 b0 [2] 56 92 [2] 42 89 [2] 4d 93 [2] 53 8e [2] 51 8f [2] 4a 89 [2] 56 8e [2] 4a a1 }

  condition:
    any of them
}