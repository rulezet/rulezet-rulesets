rule TTP_XOR_QUAD_CurrentVersionRun_295d {
  strings:
    $key_295d = { 7a 32 [2] 5e 3c [2] 75 10 [2] 5b 32 [2] 4f 29 [2] 40 33 [2] 5e 2e [2] 5c 2f [2] 47 29 [2] 5b 2e [2] 47 01 }

  condition:
    any of them
}