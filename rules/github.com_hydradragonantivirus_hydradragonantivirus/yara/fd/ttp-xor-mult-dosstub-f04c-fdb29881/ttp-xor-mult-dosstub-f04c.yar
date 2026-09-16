rule TTP_XOR_MULT_DOSStub_f04c {
  strings:
    $key_f04c = { a4 24 [2] d0 3c [2] 97 3e [2] d0 2f [2] 9e 23 [2] 92 29 [2] 85 22 [2] 9e 6c [2] a3 }

  condition:
    any of them
}