rule TTP_XOR_MULT_DOSStub_9af6 {
  strings:
    $key_9af6 = { ce 9e [2] ba 86 [2] fd 84 [2] ba 95 [2] f4 99 [2] f8 93 [2] ef 98 [2] f4 d6 [2] c9 }

  condition:
    any of them
}