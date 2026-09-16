rule TTP_XOR_MULT_DOSStub_9ae2 {
  strings:
    $key_9ae2 = { ce 8a [2] ba 92 [2] fd 90 [2] ba 81 [2] f4 8d [2] f8 87 [2] ef 8c [2] f4 c2 [2] c9 }

  condition:
    any of them
}