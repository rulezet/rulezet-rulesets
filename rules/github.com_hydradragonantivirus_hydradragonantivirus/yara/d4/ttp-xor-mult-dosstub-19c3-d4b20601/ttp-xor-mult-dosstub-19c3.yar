rule TTP_XOR_MULT_DOSStub_19c3 {
  strings:
    $key_19c3 = { 4d ab [2] 39 b3 [2] 7e b1 [2] 39 a0 [2] 77 ac [2] 7b a6 [2] 6c ad [2] 77 e3 [2] 4a }

  condition:
    any of them
}