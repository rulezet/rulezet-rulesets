rule TTP_XOR_MULT_DOSStub_f16d {
  strings:
    $key_f16d = { a5 05 [2] d1 1d [2] 96 1f [2] d1 0e [2] 9f 02 [2] 93 08 [2] 84 03 [2] 9f 4d [2] a2 }

  condition:
    any of them
}