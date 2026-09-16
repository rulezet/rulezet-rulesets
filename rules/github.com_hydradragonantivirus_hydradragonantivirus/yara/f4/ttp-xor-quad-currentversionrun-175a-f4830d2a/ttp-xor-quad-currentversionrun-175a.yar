rule TTP_XOR_QUAD_CurrentVersionRun_175a {
  strings:
    $key_175a = { 44 35 [2] 60 3b [2] 4b 17 [2] 65 35 [2] 71 2e [2] 7e 34 [2] 60 29 [2] 62 28 [2] 79 2e [2] 65 29 [2] 79 06 }

  condition:
    any of them
}