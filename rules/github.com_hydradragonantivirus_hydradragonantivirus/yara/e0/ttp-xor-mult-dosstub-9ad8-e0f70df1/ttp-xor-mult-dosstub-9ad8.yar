rule TTP_XOR_MULT_DOSStub_9ad8 {
  strings:
    $key_9ad8 = { ce b0 [2] ba a8 [2] fd aa [2] ba bb [2] f4 b7 [2] f8 bd [2] ef b6 [2] f4 f8 [2] c9 }

  condition:
    any of them
}