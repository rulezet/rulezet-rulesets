rule TTP_XOR_QUAD_CurrentVersionRun_63fd {
  strings:
    $key_63fd = { 30 92 [2] 14 9c [2] 3f b0 [2] 11 92 [2] 05 89 [2] 0a 93 [2] 14 8e [2] 16 8f [2] 0d 89 [2] 11 8e [2] 0d a1 }

  condition:
    any of them
}