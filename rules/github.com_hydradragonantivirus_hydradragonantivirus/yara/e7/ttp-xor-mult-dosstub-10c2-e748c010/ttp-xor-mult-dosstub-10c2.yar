rule TTP_XOR_MULT_DOSStub_10c2 {
  strings:
    $key_10c2 = { 44 aa [2] 30 b2 [2] 77 b0 [2] 30 a1 [2] 7e ad [2] 72 a7 [2] 65 ac [2] 7e e2 [2] 43 }

  condition:
    any of them
}