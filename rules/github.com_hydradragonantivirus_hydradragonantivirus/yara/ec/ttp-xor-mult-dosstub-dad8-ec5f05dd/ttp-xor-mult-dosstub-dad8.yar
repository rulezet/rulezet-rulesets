rule TTP_XOR_MULT_DOSStub_dad8 {
  strings:
    $key_dad8 = { 8e b0 [2] fa a8 [2] bd aa [2] fa bb [2] b4 b7 [2] b8 bd [2] af b6 [2] b4 f8 [2] 89 }

  condition:
    any of them
}