rule TTP_XOR_MULT_DOSStub_9ae4 {
  strings:
    $key_9ae4 = { ce 8c [2] ba 94 [2] fd 96 [2] ba 87 [2] f4 8b [2] f8 81 [2] ef 8a [2] f4 c4 [2] c9 }

  condition:
    any of them
}