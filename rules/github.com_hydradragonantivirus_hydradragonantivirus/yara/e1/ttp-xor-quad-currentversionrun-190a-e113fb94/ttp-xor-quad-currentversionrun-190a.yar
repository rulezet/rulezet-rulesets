rule TTP_XOR_QUAD_CurrentVersionRun_190a {
  strings:
    $key_190a = { 4a 65 [2] 6e 6b [2] 45 47 [2] 6b 65 [2] 7f 7e [2] 70 64 [2] 6e 79 [2] 6c 78 [2] 77 7e [2] 6b 79 [2] 77 56 }

  condition:
    any of them
}