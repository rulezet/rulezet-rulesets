rule TTP_XOR_QUAD_CurrentVersionRun_605d {
  strings:
    $key_605d = { 33 32 [2] 17 3c [2] 3c 10 [2] 12 32 [2] 06 29 [2] 09 33 [2] 17 2e [2] 15 2f [2] 0e 29 [2] 12 2e [2] 0e 01 }

  condition:
    any of them
}