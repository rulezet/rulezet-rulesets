rule TTP_XOR_MULT_DOSStub_9add {
  strings:
    $key_9add = { ce b5 [2] ba ad [2] fd af [2] ba be [2] f4 b2 [2] f8 b8 [2] ef b3 [2] f4 fd [2] c9 }

  condition:
    any of them
}