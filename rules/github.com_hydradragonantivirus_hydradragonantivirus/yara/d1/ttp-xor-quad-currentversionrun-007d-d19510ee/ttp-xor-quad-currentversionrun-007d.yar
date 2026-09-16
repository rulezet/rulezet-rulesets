rule TTP_XOR_QUAD_CurrentVersionRun_007d {
  strings:
    $key_007d = { 53 12 [2] 77 1c [2] 5c 30 [2] 72 12 [2] 66 09 [2] 69 13 [2] 77 0e [2] 75 0f [2] 6e 09 [2] 72 0e [2] 6e 21 }

  condition:
    any of them
}