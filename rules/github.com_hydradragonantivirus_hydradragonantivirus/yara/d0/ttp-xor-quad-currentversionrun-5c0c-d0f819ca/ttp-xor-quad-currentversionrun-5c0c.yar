rule TTP_XOR_QUAD_CurrentVersionRun_5c0c {
  strings:
    $key_5c0c = { 0f 63 [2] 2b 6d [2] 00 41 [2] 2e 63 [2] 3a 78 [2] 35 62 [2] 2b 7f [2] 29 7e [2] 32 78 [2] 2e 7f [2] 32 50 }

  condition:
    any of them
}