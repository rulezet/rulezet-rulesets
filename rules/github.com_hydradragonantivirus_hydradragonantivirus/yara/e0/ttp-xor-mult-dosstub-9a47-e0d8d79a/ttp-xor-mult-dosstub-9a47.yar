rule TTP_XOR_MULT_DOSStub_9a47 {
  strings:
    $key_9a47 = { ce 2f [2] ba 37 [2] fd 35 [2] ba 24 [2] f4 28 [2] f8 22 [2] ef 29 [2] f4 67 [2] c9 }

  condition:
    any of them
}