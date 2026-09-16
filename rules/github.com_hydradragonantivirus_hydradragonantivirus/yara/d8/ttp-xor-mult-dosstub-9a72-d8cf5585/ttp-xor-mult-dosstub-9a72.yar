rule TTP_XOR_MULT_DOSStub_9a72 {
  strings:
    $key_9a72 = { ce 1a [2] ba 02 [2] fd 00 [2] ba 11 [2] f4 1d [2] f8 17 [2] ef 1c [2] f4 52 [2] c9 }

  condition:
    any of them
}