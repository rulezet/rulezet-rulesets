rule TTP_XOR_MULT_DOSStub_f01c {
  strings:
    $key_f01c = { a4 74 [2] d0 6c [2] 97 6e [2] d0 7f [2] 9e 73 [2] 92 79 [2] 85 72 [2] 9e 3c [2] a3 }

  condition:
    any of them
}