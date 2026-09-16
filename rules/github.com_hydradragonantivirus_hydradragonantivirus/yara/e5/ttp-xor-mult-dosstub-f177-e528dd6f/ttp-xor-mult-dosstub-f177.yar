rule TTP_XOR_MULT_DOSStub_f177 {
  strings:
    $key_f177 = { a5 1f [2] d1 07 [2] 96 05 [2] d1 14 [2] 9f 18 [2] 93 12 [2] 84 19 [2] 9f 57 [2] a2 }

  condition:
    any of them
}