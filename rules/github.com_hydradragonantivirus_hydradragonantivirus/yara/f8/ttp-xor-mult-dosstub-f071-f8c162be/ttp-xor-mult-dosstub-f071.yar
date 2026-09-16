rule TTP_XOR_MULT_DOSStub_f071 {
  strings:
    $key_f071 = { a4 19 [2] d0 01 [2] 97 03 [2] d0 12 [2] 9e 1e [2] 92 14 [2] 85 1f [2] 9e 51 [2] a3 }

  condition:
    any of them
}