rule TTP_XOR_QUAD_CurrentVersionRun_0c4a {
  strings:
    $key_0c4a = { 5f 25 [2] 7b 2b [2] 50 07 [2] 7e 25 [2] 6a 3e [2] 65 24 [2] 7b 39 [2] 79 38 [2] 62 3e [2] 7e 39 [2] 62 16 }

  condition:
    any of them
}