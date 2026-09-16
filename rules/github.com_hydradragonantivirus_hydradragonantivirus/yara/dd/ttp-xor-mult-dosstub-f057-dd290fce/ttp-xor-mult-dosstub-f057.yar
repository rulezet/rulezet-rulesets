rule TTP_XOR_MULT_DOSStub_f057 {
  strings:
    $key_f057 = { a4 3f [2] d0 27 [2] 97 25 [2] d0 34 [2] 9e 38 [2] 92 32 [2] 85 39 [2] 9e 77 [2] a3 }

  condition:
    any of them
}