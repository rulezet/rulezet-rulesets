rule TTP_XOR_QUAD_CurrentVersionRun_355d {
  strings:
    $key_355d = { 66 32 [2] 42 3c [2] 69 10 [2] 47 32 [2] 53 29 [2] 5c 33 [2] 42 2e [2] 40 2f [2] 5b 29 [2] 47 2e [2] 5b 01 }

  condition:
    any of them
}