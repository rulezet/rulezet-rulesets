rule TTP_XOR_MULT_DOSStub_24e7 {
  strings:
    $key_24e7 = { 70 8f [2] 04 97 [2] 43 95 [2] 04 84 [2] 4a 88 [2] 46 82 [2] 51 89 [2] 4a c7 [2] 77 }

  condition:
    any of them
}