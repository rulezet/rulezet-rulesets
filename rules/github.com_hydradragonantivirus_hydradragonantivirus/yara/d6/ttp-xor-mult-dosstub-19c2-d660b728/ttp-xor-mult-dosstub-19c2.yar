rule TTP_XOR_MULT_DOSStub_19c2 {
  strings:
    $key_19c2 = { 4d aa [2] 39 b2 [2] 7e b0 [2] 39 a1 [2] 77 ad [2] 7b a7 [2] 6c ac [2] 77 e2 [2] 4a }

  condition:
    any of them
}