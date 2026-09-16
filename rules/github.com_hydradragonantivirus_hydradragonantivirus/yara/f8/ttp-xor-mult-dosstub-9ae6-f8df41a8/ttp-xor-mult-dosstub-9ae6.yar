rule TTP_XOR_MULT_DOSStub_9ae6 {
  strings:
    $key_9ae6 = { ce 8e [2] ba 96 [2] fd 94 [2] ba 85 [2] f4 89 [2] f8 83 [2] ef 88 [2] f4 c6 [2] c9 }

  condition:
    any of them
}