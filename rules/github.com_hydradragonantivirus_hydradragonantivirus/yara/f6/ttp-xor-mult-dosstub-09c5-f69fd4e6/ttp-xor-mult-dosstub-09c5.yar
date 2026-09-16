rule TTP_XOR_MULT_DOSStub_09c5 {
  strings:
    $key_09c5 = { 5d ad [2] 29 b5 [2] 6e b7 [2] 29 a6 [2] 67 aa [2] 6b a0 [2] 7c ab [2] 67 e5 [2] 5a }

  condition:
    any of them
}