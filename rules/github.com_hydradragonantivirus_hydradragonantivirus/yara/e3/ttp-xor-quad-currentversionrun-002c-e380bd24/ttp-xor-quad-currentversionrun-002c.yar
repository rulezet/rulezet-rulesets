rule TTP_XOR_QUAD_CurrentVersionRun_002c {
  strings:
    $key_002c = { 53 43 [2] 77 4d [2] 5c 61 [2] 72 43 [2] 66 58 [2] 69 42 [2] 77 5f [2] 75 5e [2] 6e 58 [2] 72 5f [2] 6e 70 }

  condition:
    any of them
}