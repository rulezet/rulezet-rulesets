rule TTP_XOR_MULT_DOSStub_f541 {
  strings:
    $key_f541 = { a1 29 [2] d5 31 [2] 92 33 [2] d5 22 [2] 9b 2e [2] 97 24 [2] 80 2f [2] 9b 61 [2] a6 }

  condition:
    any of them
}