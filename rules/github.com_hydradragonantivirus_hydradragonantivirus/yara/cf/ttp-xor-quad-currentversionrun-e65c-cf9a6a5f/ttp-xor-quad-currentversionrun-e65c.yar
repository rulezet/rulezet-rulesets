rule TTP_XOR_QUAD_CurrentVersionRun_e65c {
  strings:
    $key_e65c = { b5 33 [2] 91 3d [2] ba 11 [2] 94 33 [2] 80 28 [2] 8f 32 [2] 91 2f [2] 93 2e [2] 88 28 [2] 94 2f [2] 88 00 }

  condition:
    any of them
}