rule TTP_XOR_MULT_DOSStub_f75c {
  strings:
    $key_f75c = { a3 34 [2] d7 2c [2] 90 2e [2] d7 3f [2] 99 33 [2] 95 39 [2] 82 32 [2] 99 7c [2] a4 }

  condition:
    any of them
}