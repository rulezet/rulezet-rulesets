rule TTP_XOR_QUAD_CurrentVersionRun_405d {
  strings:
    $key_405d = { 13 32 [2] 37 3c [2] 1c 10 [2] 32 32 [2] 26 29 [2] 29 33 [2] 37 2e [2] 35 2f [2] 2e 29 [2] 32 2e [2] 2e 01 }

  condition:
    any of them
}