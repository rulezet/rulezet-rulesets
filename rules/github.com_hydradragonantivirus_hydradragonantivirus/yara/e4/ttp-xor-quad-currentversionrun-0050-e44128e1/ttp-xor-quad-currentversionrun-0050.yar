rule TTP_XOR_QUAD_CurrentVersionRun_0050 {
  strings:
    $key_0050 = { 53 3f [2] 77 31 [2] 5c 1d [2] 72 3f [2] 66 24 [2] 69 3e [2] 77 23 [2] 75 22 [2] 6e 24 [2] 72 23 [2] 6e 0c }

  condition:
    any of them
}