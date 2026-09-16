rule TTP_XOR_MULT_DOSStub_242a {
  strings:
    $key_242a = { 70 42 [2] 04 5a [2] 43 58 [2] 04 49 [2] 4a 45 [2] 46 4f [2] 51 44 [2] 4a 0a [2] 77 }

  condition:
    any of them
}