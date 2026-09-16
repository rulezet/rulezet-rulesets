rule TTP_XOR_MULT_DOSStub_93d8 {
  strings:
    $key_93d8 = { c7 b0 [2] b3 a8 [2] f4 aa [2] b3 bb [2] fd b7 [2] f1 bd [2] e6 b6 [2] fd f8 [2] c0 }

  condition:
    any of them
}