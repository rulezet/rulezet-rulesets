rule TTP_XOR_MULT_DOSStub_f51c {
  strings:
    $key_f51c = { a1 74 [2] d5 6c [2] 92 6e [2] d5 7f [2] 9b 73 [2] 97 79 [2] 80 72 [2] 9b 3c [2] a6 }

  condition:
    any of them
}