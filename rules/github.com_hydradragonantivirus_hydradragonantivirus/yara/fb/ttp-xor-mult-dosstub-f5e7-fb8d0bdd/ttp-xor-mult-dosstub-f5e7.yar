rule TTP_XOR_MULT_DOSStub_f5e7 {
  strings:
    $key_f5e7 = { a1 8f [2] d5 97 [2] 92 95 [2] d5 84 [2] 9b 88 [2] 97 82 [2] 80 89 [2] 9b c7 [2] a6 }

  condition:
    any of them
}