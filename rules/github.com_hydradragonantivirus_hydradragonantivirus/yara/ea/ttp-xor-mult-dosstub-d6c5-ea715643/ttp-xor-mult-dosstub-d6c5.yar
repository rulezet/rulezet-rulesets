rule TTP_XOR_MULT_DOSStub_d6c5 {
  strings:
    $key_d6c5 = { 82 ad [2] f6 b5 [2] b1 b7 [2] f6 a6 [2] b8 aa [2] b4 a0 [2] a3 ab [2] b8 e5 [2] 85 }

  condition:
    any of them
}