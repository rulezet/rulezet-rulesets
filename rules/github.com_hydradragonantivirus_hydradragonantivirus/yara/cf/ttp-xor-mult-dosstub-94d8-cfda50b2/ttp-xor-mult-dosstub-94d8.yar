rule TTP_XOR_MULT_DOSStub_94d8 {
  strings:
    $key_94d8 = { c0 b0 [2] b4 a8 [2] f3 aa [2] b4 bb [2] fa b7 [2] f6 bd [2] e1 b6 [2] fa f8 [2] c7 }

  condition:
    any of them
}