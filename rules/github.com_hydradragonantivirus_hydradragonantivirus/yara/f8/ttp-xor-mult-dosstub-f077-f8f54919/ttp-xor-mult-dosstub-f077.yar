rule TTP_XOR_MULT_DOSStub_f077 {
  strings:
    $key_f077 = { a4 1f [2] d0 07 [2] 97 05 [2] d0 14 [2] 9e 18 [2] 92 12 [2] 85 19 [2] 9e 57 [2] a3 }

  condition:
    any of them
}