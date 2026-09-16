rule TTP_XOR_QUAD_CurrentVersionRun_001d {
  strings:
    $key_001d = { 53 72 [2] 77 7c [2] 5c 50 [2] 72 72 [2] 66 69 [2] 69 73 [2] 77 6e [2] 75 6f [2] 6e 69 [2] 72 6e [2] 6e 41 }

  condition:
    any of them
}