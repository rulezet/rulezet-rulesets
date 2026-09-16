rule TTP_XOR_MULT_DOSStub_94c2 {
  strings:
    $key_94c2 = { c0 aa [2] b4 b2 [2] f3 b0 [2] b4 a1 [2] fa ad [2] f6 a7 [2] e1 ac [2] fa e2 [2] c7 }

  condition:
    any of them
}