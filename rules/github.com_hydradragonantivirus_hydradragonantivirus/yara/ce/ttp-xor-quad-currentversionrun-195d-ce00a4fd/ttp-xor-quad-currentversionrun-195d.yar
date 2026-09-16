rule TTP_XOR_QUAD_CurrentVersionRun_195d {
  strings:
    $key_195d = { 4a 32 [2] 6e 3c [2] 45 10 [2] 6b 32 [2] 7f 29 [2] 70 33 [2] 6e 2e [2] 6c 2f [2] 77 29 [2] 6b 2e [2] 77 01 }

  condition:
    any of them
}