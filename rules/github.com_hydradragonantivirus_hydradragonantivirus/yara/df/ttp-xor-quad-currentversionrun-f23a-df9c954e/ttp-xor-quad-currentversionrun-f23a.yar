rule TTP_XOR_QUAD_CurrentVersionRun_f23a {
  strings:
    $key_f23a = { a1 55 [2] 85 5b [2] ae 77 [2] 80 55 [2] 94 4e [2] 9b 54 [2] 85 49 [2] 87 48 [2] 9c 4e [2] 80 49 [2] 9c 66 }

  condition:
    any of them
}