rule TTP_XOR_QUAD_CurrentVersionRun_4c0a {
  strings:
    $key_4c0a = { 1f 65 [2] 3b 6b [2] 10 47 [2] 3e 65 [2] 2a 7e [2] 25 64 [2] 3b 79 [2] 39 78 [2] 22 7e [2] 3e 79 [2] 22 56 }

  condition:
    any of them
}