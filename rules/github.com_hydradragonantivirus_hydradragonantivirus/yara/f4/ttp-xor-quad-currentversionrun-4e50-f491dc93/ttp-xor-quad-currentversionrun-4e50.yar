rule TTP_XOR_QUAD_CurrentVersionRun_4e50 {
  strings:
    $key_4e50 = { 1d 3f [2] 39 31 [2] 12 1d [2] 3c 3f [2] 28 24 [2] 27 3e [2] 39 23 [2] 3b 22 [2] 20 24 [2] 3c 23 [2] 20 0c }

  condition:
    any of them
}