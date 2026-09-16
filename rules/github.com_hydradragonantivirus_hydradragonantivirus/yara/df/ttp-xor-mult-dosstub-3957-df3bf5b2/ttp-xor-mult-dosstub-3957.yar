rule TTP_XOR_MULT_DOSStub_3957 {
  strings:
    $key_3957 = { 6d 3f [2] 19 27 [2] 5e 25 [2] 19 34 [2] 57 38 [2] 5b 32 [2] 4c 39 [2] 57 77 [2] 6a }

  condition:
    any of them
}