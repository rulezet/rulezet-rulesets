rule TTP_XOR_QUAD_CurrentVersionRun_194a {
  strings:
    $key_194a = { 4a 25 [2] 6e 2b [2] 45 07 [2] 6b 25 [2] 7f 3e [2] 70 24 [2] 6e 39 [2] 6c 38 [2] 77 3e [2] 6b 39 [2] 77 16 }

  condition:
    any of them
}