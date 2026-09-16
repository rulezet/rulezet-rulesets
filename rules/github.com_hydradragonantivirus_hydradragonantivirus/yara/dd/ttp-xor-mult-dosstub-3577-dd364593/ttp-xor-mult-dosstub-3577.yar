rule TTP_XOR_MULT_DOSStub_3577 {
  strings:
    $key_3577 = { 61 1f [2] 15 07 [2] 52 05 [2] 15 14 [2] 5b 18 [2] 57 12 [2] 40 19 [2] 5b 57 [2] 66 }

  condition:
    any of them
}