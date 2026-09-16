rule TTP_XOR_MULT_DOSStub_9a38 {
  strings:
    $key_9a38 = { ce 50 [2] ba 48 [2] fd 4a [2] ba 5b [2] f4 57 [2] f8 5d [2] ef 56 [2] f4 18 [2] c9 }

  condition:
    any of them
}