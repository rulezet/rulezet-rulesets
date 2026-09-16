rule TTP_XOR_MULT_DOSStub_f40d {
  strings:
    $key_f40d = { a0 65 [2] d4 7d [2] 93 7f [2] d4 6e [2] 9a 62 [2] 96 68 [2] 81 63 [2] 9a 2d [2] a7 }

  condition:
    any of them
}