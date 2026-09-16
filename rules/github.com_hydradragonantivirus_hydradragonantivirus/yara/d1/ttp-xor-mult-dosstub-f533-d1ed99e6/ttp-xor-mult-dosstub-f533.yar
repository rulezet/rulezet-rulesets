rule TTP_XOR_MULT_DOSStub_f533 {
  strings:
    $key_f533 = { a1 5b [2] d5 43 [2] 92 41 [2] d5 50 [2] 9b 5c [2] 97 56 [2] 80 5d [2] 9b 13 [2] a6 }

  condition:
    any of them
}