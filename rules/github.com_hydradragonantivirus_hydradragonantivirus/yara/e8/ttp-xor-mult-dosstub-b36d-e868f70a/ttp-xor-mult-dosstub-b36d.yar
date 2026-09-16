rule TTP_XOR_MULT_DOSStub_b36d {
  strings:
    $key_b36d = { e7 05 [2] 93 1d [2] d4 1f [2] 93 0e [2] dd 02 [2] d1 08 [2] c6 03 [2] dd 4d [2] e0 }

  condition:
    any of them
}