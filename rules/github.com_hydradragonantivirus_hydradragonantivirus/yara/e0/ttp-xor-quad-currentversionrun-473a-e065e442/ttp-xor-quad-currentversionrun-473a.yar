rule TTP_XOR_QUAD_CurrentVersionRun_473a {
  strings:
    $key_473a = { 14 55 [2] 30 5b [2] 1b 77 [2] 35 55 [2] 21 4e [2] 2e 54 [2] 30 49 [2] 32 48 [2] 29 4e [2] 35 49 [2] 29 66 }

  condition:
    any of them
}