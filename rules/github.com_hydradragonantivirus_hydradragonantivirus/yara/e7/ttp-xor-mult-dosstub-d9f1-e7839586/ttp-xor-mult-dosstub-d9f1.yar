rule TTP_XOR_MULT_DOSStub_d9f1 {
  strings:
    $key_d9f1 = { 8d 99 [2] f9 81 [2] be 83 [2] f9 92 [2] b7 9e [2] bb 94 [2] ac 9f [2] b7 d1 [2] 8a }

  condition:
    any of them
}