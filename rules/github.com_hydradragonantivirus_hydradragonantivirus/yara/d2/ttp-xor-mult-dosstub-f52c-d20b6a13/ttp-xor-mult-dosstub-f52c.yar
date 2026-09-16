rule TTP_XOR_MULT_DOSStub_f52c {
  strings:
    $key_f52c = { a1 44 [2] d5 5c [2] 92 5e [2] d5 4f [2] 9b 43 [2] 97 49 [2] 80 42 [2] 9b 0c [2] a6 }

  condition:
    any of them
}