rule TTP_XOR_MULT_DOSStub_d946 {
  strings:
    $key_d946 = { 8d 2e [2] f9 36 [2] be 34 [2] f9 25 [2] b7 29 [2] bb 23 [2] ac 28 [2] b7 66 [2] 8a }

  condition:
    any of them
}