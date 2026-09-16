rule TTP_XOR_QUAD_CurrentVersionRun_2b5d {
  strings:
    $key_2b5d = { 78 32 [2] 5c 3c [2] 77 10 [2] 59 32 [2] 4d 29 [2] 42 33 [2] 5c 2e [2] 5e 2f [2] 45 29 [2] 59 2e [2] 45 01 }

  condition:
    any of them
}