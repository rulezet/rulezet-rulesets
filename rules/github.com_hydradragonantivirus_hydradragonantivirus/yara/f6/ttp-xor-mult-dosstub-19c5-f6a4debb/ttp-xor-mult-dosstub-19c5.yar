rule TTP_XOR_MULT_DOSStub_19c5 {
  strings:
    $key_19c5 = { 4d ad [2] 39 b5 [2] 7e b7 [2] 39 a6 [2] 77 aa [2] 7b a0 [2] 6c ab [2] 77 e5 [2] 4a }

  condition:
    any of them
}