rule TTP_XOR_MULT_DOSStub_79c5 {
  strings:
    $key_79c5 = { 2d ad [2] 59 b5 [2] 1e b7 [2] 59 a6 [2] 17 aa [2] 1b a0 [2] 0c ab [2] 17 e5 [2] 2a }

  condition:
    any of them
}