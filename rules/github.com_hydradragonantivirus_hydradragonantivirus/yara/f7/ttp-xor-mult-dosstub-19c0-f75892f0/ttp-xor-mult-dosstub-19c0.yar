rule TTP_XOR_MULT_DOSStub_19c0 {
  strings:
    $key_19c0 = { 4d a8 [2] 39 b0 [2] 7e b2 [2] 39 a3 [2] 77 af [2] 7b a5 [2] 6c ae [2] 77 e0 [2] 4a }

  condition:
    any of them
}