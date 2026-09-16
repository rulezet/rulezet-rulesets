rule TTP_XOR_MULT_DOSStub_f54c {
  strings:
    $key_f54c = { a1 24 [2] d5 3c [2] 92 3e [2] d5 2f [2] 9b 23 [2] 97 29 [2] 80 22 [2] 9b 6c [2] a6 }

  condition:
    any of them
}