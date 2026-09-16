rule TTP_XOR_MULT_DOSStub_1927 {
  strings:
    $key_1927 = { 4d 4f [2] 39 57 [2] 7e 55 [2] 39 44 [2] 77 48 [2] 7b 42 [2] 6c 49 [2] 77 07 [2] 4a }

  condition:
    any of them
}