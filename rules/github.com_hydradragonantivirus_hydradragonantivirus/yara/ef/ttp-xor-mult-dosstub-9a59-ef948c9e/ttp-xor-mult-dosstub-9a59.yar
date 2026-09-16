rule TTP_XOR_MULT_DOSStub_9a59 {
  strings:
    $key_9a59 = { ce 31 [2] ba 29 [2] fd 2b [2] ba 3a [2] f4 36 [2] f8 3c [2] ef 37 [2] f4 79 [2] c9 }

  condition:
    any of them
}