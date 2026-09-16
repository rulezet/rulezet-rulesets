rule TTP_XOR_QUAD_CurrentVersionRun_e65d {
  strings:
    $key_e65d = { b5 32 [2] 91 3c [2] ba 10 [2] 94 32 [2] 80 29 [2] 8f 33 [2] 91 2e [2] 93 2f [2] 88 29 [2] 94 2e [2] 88 01 }

  condition:
    any of them
}