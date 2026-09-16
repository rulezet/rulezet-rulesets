rule TTP_XOR_MULT_DOSStub_7177 {
  strings:
    $key_7177 = { 25 1f [2] 51 07 [2] 16 05 [2] 51 14 [2] 1f 18 [2] 13 12 [2] 04 19 [2] 1f 57 [2] 22 }

  condition:
    any of them
}