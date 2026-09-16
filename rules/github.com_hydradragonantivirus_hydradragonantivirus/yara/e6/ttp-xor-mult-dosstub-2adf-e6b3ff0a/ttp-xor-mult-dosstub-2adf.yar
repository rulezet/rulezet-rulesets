rule TTP_XOR_MULT_DOSStub_2adf {
  strings:
    $key_2adf = { 7e b7 [2] 0a af [2] 4d ad [2] 0a bc [2] 44 b0 [2] 48 ba [2] 5f b1 [2] 44 ff [2] 79 }

  condition:
    any of them
}