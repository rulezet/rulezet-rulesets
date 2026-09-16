rule TTP_XOR_QUAD_CurrentVersionRun_5c2d {
  strings:
    $key_5c2d = { 0f 42 [2] 2b 4c [2] 00 60 [2] 2e 42 [2] 3a 59 [2] 35 43 [2] 2b 5e [2] 29 5f [2] 32 59 [2] 2e 5e [2] 32 71 }

  condition:
    any of them
}