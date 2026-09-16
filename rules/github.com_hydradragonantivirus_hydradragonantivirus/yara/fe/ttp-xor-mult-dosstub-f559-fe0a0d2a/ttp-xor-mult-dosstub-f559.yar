rule TTP_XOR_MULT_DOSStub_f559 {
  strings:
    $key_f559 = { a1 31 [2] d5 29 [2] 92 2b [2] d5 3a [2] 9b 36 [2] 97 3c [2] 80 37 [2] 9b 79 [2] a6 }

  condition:
    any of them
}