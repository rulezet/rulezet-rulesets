rule TTP_XOR_MULT_DOSStub_9a04 {
  strings:
    $key_9a04 = { ce 6c [2] ba 74 [2] fd 76 [2] ba 67 [2] f4 6b [2] f8 61 [2] ef 6a [2] f4 24 [2] c9 }

  condition:
    any of them
}