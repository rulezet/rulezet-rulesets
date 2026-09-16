rule TTP_XOR_QUAD_CurrentVersionRun_fa5d {
  strings:
    $key_fa5d = { a9 32 [2] 8d 3c [2] a6 10 [2] 88 32 [2] 9c 29 [2] 93 33 [2] 8d 2e [2] 8f 2f [2] 94 29 [2] 88 2e [2] 94 01 }

  condition:
    any of them
}