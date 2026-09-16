rule TTP_XOR_MULT_DOSStub_35e7 {
  strings:
    $key_35e7 = { 61 8f [2] 15 97 [2] 52 95 [2] 15 84 [2] 5b 88 [2] 57 82 [2] 40 89 [2] 5b c7 [2] 66 }

  condition:
    any of them
}