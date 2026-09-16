rule TTP_XOR_MULT_DOSStub_f507 {
  strings:
    $key_f507 = { a1 6f [2] d5 77 [2] 92 75 [2] d5 64 [2] 9b 68 [2] 97 62 [2] 80 69 [2] 9b 27 [2] a6 }

  condition:
    any of them
}