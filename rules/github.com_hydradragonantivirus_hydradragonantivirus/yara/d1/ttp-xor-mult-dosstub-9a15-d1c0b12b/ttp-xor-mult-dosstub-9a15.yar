rule TTP_XOR_MULT_DOSStub_9a15 {
  strings:
    $key_9a15 = { ce 7d [2] ba 65 [2] fd 67 [2] ba 76 [2] f4 7a [2] f8 70 [2] ef 7b [2] f4 35 [2] c9 }

  condition:
    any of them
}