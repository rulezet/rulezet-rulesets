rule TTP_XOR_QUAD_CurrentVersionRun_1e0a {
  strings:
    $key_1e0a = { 4d 65 [2] 69 6b [2] 42 47 [2] 6c 65 [2] 78 7e [2] 77 64 [2] 69 79 [2] 6b 78 [2] 70 7e [2] 6c 79 [2] 70 56 }

  condition:
    any of them
}