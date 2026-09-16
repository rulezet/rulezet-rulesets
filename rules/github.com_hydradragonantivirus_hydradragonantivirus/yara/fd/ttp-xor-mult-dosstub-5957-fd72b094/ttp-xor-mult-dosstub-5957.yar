rule TTP_XOR_MULT_DOSStub_5957 {
  strings:
    $key_5957 = { 0d 3f [2] 79 27 [2] 3e 25 [2] 79 34 [2] 37 38 [2] 3b 32 [2] 2c 39 [2] 37 77 [2] 0a }

  condition:
    any of them
}