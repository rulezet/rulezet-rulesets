rule TTP_XOR_MULT_DOSStub_f557 {
  strings:
    $key_f557 = { a1 3f [2] d5 27 [2] 92 25 [2] d5 34 [2] 9b 38 [2] 97 32 [2] 80 39 [2] 9b 77 [2] a6 }

  condition:
    any of them
}