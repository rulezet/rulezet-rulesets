rule TTP_XOR_MULT_DOSStub_1962 {
  strings:
    $key_1962 = { 4d 0a [2] 39 12 [2] 7e 10 [2] 39 01 [2] 77 0d [2] 7b 07 [2] 6c 0c [2] 77 42 [2] 4a }

  condition:
    any of them
}