rule TTP_XOR_MULT_DOSStub_91c4 {
  strings:
    $key_91c4 = { c5 ac [2] b1 b4 [2] f6 b6 [2] b1 a7 [2] ff ab [2] f3 a1 [2] e4 aa [2] ff e4 [2] c2 }

  condition:
    any of them
}