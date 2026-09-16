rule TTP_XOR_QUAD_CurrentVersionRun_445d {
  strings:
    $key_445d = { 17 32 [2] 33 3c [2] 18 10 [2] 36 32 [2] 22 29 [2] 2d 33 [2] 33 2e [2] 31 2f [2] 2a 29 [2] 36 2e [2] 2a 01 }

  condition:
    any of them
}