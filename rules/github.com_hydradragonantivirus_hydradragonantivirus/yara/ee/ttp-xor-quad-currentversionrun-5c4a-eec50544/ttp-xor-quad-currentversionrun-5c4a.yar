rule TTP_XOR_QUAD_CurrentVersionRun_5c4a {
  strings:
    $key_5c4a = { 0f 25 [2] 2b 2b [2] 00 07 [2] 2e 25 [2] 3a 3e [2] 35 24 [2] 2b 39 [2] 29 38 [2] 32 3e [2] 2e 39 [2] 32 16 }

  condition:
    any of them
}