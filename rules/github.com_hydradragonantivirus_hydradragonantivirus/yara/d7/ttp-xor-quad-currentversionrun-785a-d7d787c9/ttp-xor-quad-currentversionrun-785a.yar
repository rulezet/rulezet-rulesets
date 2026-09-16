rule TTP_XOR_QUAD_CurrentVersionRun_785a {
  strings:
    $key_785a = { 2b 35 [2] 0f 3b [2] 24 17 [2] 0a 35 [2] 1e 2e [2] 11 34 [2] 0f 29 [2] 0d 28 [2] 16 2e [2] 0a 29 [2] 16 06 }

  condition:
    any of them
}