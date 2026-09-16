rule TTP_XOR_QUAD_CurrentVersionRun_022a {
  strings:
    $key_022a = { 51 45 [2] 75 4b [2] 5e 67 [2] 70 45 [2] 64 5e [2] 6b 44 [2] 75 59 [2] 77 58 [2] 6c 5e [2] 70 59 [2] 6c 76 }

  condition:
    any of them
}