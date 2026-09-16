rule TTP_XOR_QUAD_CurrentVersionRun_f85d {
  strings:
    $key_f85d = { ab 32 [2] 8f 3c [2] a4 10 [2] 8a 32 [2] 9e 29 [2] 91 33 [2] 8f 2e [2] 8d 2f [2] 96 29 [2] 8a 2e [2] 96 01 }

  condition:
    any of them
}