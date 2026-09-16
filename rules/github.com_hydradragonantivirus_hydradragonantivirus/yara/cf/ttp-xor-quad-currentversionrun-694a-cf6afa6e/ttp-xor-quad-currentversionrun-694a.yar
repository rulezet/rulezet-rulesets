rule TTP_XOR_QUAD_CurrentVersionRun_694a {
  strings:
    $key_694a = { 3a 25 [2] 1e 2b [2] 35 07 [2] 1b 25 [2] 0f 3e [2] 00 24 [2] 1e 39 [2] 1c 38 [2] 07 3e [2] 1b 39 [2] 07 16 }

  condition:
    any of them
}