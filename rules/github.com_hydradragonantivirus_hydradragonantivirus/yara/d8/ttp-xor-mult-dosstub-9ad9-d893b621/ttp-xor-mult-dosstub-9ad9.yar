rule TTP_XOR_MULT_DOSStub_9ad9 {
  strings:
    $key_9ad9 = { ce b1 [2] ba a9 [2] fd ab [2] ba ba [2] f4 b6 [2] f8 bc [2] ef b7 [2] f4 f9 [2] c9 }

  condition:
    any of them
}