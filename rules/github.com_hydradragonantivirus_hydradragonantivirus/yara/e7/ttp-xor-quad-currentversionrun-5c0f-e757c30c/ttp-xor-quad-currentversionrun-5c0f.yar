rule TTP_XOR_QUAD_CurrentVersionRun_5c0f {
  strings:
    $key_5c0f = { 0f 60 [2] 2b 6e [2] 00 42 [2] 2e 60 [2] 3a 7b [2] 35 61 [2] 2b 7c [2] 29 7d [2] 32 7b [2] 2e 7c [2] 32 53 }

  condition:
    any of them
}