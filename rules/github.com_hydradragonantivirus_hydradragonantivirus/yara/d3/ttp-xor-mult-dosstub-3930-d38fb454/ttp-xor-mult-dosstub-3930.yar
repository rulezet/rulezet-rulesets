rule TTP_XOR_MULT_DOSStub_3930 {
  strings:
    $key_3930 = { 6d 58 [2] 19 40 [2] 5e 42 [2] 19 53 [2] 57 5f [2] 5b 55 [2] 4c 5e [2] 57 10 [2] 6a }

  condition:
    any of them
}