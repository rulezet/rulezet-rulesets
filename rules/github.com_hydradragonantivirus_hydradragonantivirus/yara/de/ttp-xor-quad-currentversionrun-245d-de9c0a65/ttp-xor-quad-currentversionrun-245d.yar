rule TTP_XOR_QUAD_CurrentVersionRun_245d {
  strings:
    $key_245d = { 77 32 [2] 53 3c [2] 78 10 [2] 56 32 [2] 42 29 [2] 4d 33 [2] 53 2e [2] 51 2f [2] 4a 29 [2] 56 2e [2] 4a 01 }

  condition:
    any of them
}