rule TTP_XOR_MULT_DOSStub_fdc2 {
  strings:
    $key_fdc2 = { a9 aa [2] dd b2 [2] 9a b0 [2] dd a1 [2] 93 ad [2] 9f a7 [2] 88 ac [2] 93 e2 [2] ae }

  condition:
    any of them
}