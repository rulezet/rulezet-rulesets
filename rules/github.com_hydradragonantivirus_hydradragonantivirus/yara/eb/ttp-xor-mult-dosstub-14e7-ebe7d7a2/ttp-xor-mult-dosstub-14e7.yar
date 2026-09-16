rule TTP_XOR_MULT_DOSStub_14e7 {
  strings:
    $key_14e7 = { 40 8f [2] 34 97 [2] 73 95 [2] 34 84 [2] 7a 88 [2] 76 82 [2] 61 89 [2] 7a c7 [2] 47 }

  condition:
    any of them
}