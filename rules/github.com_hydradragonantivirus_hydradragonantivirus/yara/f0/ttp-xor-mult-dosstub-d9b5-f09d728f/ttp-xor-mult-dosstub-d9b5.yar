rule TTP_XOR_MULT_DOSStub_d9b5 {
  strings:
    $key_d9b5 = { 8d dd [2] f9 c5 [2] be c7 [2] f9 d6 [2] b7 da [2] bb d0 [2] ac db [2] b7 95 [2] 8a }

  condition:
    any of them
}