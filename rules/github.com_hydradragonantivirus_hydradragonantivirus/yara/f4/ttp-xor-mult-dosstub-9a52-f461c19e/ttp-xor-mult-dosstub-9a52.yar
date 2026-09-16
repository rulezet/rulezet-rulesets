rule TTP_XOR_MULT_DOSStub_9a52 {
  strings:
    $key_9a52 = { ce 3a [2] ba 22 [2] fd 20 [2] ba 31 [2] f4 3d [2] f8 37 [2] ef 3c [2] f4 72 [2] c9 }

  condition:
    any of them
}