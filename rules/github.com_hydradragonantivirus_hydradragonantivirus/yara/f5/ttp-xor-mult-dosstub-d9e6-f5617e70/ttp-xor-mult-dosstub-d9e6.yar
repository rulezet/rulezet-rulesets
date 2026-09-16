rule TTP_XOR_MULT_DOSStub_d9e6 {
  strings:
    $key_d9e6 = { 8d 8e [2] f9 96 [2] be 94 [2] f9 85 [2] b7 89 [2] bb 83 [2] ac 88 [2] b7 c6 [2] 8a }

  condition:
    any of them
}