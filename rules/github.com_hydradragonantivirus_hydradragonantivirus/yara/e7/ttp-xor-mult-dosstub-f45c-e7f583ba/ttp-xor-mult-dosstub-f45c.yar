rule TTP_XOR_MULT_DOSStub_f45c {
  strings:
    $key_f45c = { a0 34 [2] d4 2c [2] 93 2e [2] d4 3f [2] 9a 33 [2] 96 39 [2] 81 32 [2] 9a 7c [2] a7 }

  condition:
    any of them
}