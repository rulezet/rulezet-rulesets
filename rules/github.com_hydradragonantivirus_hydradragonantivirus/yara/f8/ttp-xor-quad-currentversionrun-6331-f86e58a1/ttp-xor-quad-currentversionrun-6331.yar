rule TTP_XOR_QUAD_CurrentVersionRun_6331 {
  strings:
    $key_6331 = { 30 5e [2] 14 50 [2] 3f 7c [2] 11 5e [2] 05 45 [2] 0a 5f [2] 14 42 [2] 16 43 [2] 0d 45 [2] 11 42 [2] 0d 6d }

  condition:
    any of them
}