rule TTP_XOR_MULT_DOSStub_4adf {
  strings:
    $key_4adf = { 1e b7 [2] 6a af [2] 2d ad [2] 6a bc [2] 24 b0 [2] 28 ba [2] 3f b1 [2] 24 ff [2] 19 }

  condition:
    any of them
}