rule TTP_XOR_QUAD_CurrentVersionRun_1e3a {
  strings:
    $key_1e3a = { 4d 55 [2] 69 5b [2] 42 77 [2] 6c 55 [2] 78 4e [2] 77 54 [2] 69 49 [2] 6b 48 [2] 70 4e [2] 6c 49 [2] 70 66 }

  condition:
    any of them
}