rule TTP_XOR_MULT_DOSStub_3157 {
  strings:
    $key_3157 = { 65 3f [2] 11 27 [2] 56 25 [2] 11 34 [2] 5f 38 [2] 53 32 [2] 44 39 [2] 5f 77 [2] 62 }

  condition:
    any of them
}