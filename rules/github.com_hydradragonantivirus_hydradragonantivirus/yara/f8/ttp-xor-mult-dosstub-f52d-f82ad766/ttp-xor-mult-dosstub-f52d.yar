rule TTP_XOR_MULT_DOSStub_f52d {
  strings:
    $key_f52d = { a1 45 [2] d5 5d [2] 92 5f [2] d5 4e [2] 9b 42 [2] 97 48 [2] 80 43 [2] 9b 0d [2] a6 }

  condition:
    any of them
}