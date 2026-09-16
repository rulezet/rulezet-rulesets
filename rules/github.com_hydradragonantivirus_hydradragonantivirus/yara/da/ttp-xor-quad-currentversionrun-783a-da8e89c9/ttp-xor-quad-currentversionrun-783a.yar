rule TTP_XOR_QUAD_CurrentVersionRun_783a {
  strings:
    $key_783a = { 2b 55 [2] 0f 5b [2] 24 77 [2] 0a 55 [2] 1e 4e [2] 11 54 [2] 0f 49 [2] 0d 48 [2] 16 4e [2] 0a 49 [2] 16 66 }

  condition:
    any of them
}