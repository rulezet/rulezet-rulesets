rule TTP_XOR_MULT_DOSStub_9a65 {
  strings:
    $key_9a65 = { ce 0d [2] ba 15 [2] fd 17 [2] ba 06 [2] f4 0a [2] f8 00 [2] ef 0b [2] f4 45 [2] c9 }

  condition:
    any of them
}