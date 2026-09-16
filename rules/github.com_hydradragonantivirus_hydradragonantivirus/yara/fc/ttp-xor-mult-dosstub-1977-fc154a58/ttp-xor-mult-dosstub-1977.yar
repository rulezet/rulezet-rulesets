rule TTP_XOR_MULT_DOSStub_1977 {
  strings:
    $key_1977 = { 4d 1f [2] 39 07 [2] 7e 05 [2] 39 14 [2] 77 18 [2] 7b 12 [2] 6c 19 [2] 77 57 [2] 4a }

  condition:
    any of them
}