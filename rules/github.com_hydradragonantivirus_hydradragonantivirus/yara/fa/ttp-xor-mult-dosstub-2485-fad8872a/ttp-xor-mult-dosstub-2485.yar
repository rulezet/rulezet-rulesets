rule TTP_XOR_MULT_DOSStub_2485 {
  strings:
    $key_2485 = { 70 ed [2] 04 f5 [2] 43 f7 [2] 04 e6 [2] 4a ea [2] 46 e0 [2] 51 eb [2] 4a a5 [2] 77 }

  condition:
    any of them
}