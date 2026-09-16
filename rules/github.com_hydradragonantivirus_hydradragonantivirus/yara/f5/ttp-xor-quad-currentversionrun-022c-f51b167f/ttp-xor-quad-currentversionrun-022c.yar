rule TTP_XOR_QUAD_CurrentVersionRun_022c {
  strings:
    $key_022c = { 51 43 [2] 75 4d [2] 5e 61 [2] 70 43 [2] 64 58 [2] 6b 42 [2] 75 5f [2] 77 5e [2] 6c 58 [2] 70 5f [2] 6c 70 }

  condition:
    any of them
}