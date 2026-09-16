rule TTP_XOR_MULT_DOSStub_37c2 {
  strings:
    $key_37c2 = { 63 aa [2] 17 b2 [2] 50 b0 [2] 17 a1 [2] 59 ad [2] 55 a7 [2] 42 ac [2] 59 e2 [2] 64 }

  condition:
    any of them
}