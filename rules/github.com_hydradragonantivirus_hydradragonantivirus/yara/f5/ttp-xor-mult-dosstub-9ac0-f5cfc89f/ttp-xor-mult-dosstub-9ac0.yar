rule TTP_XOR_MULT_DOSStub_9ac0 {
  strings:
    $key_9ac0 = { ce a8 [2] ba b0 [2] fd b2 [2] ba a3 [2] f4 af [2] f8 a5 [2] ef ae [2] f4 e0 [2] c9 }

  condition:
    any of them
}