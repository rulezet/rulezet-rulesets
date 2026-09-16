rule TTP_XOR_MULT_DOSStub_9a21 {
  strings:
    $key_9a21 = { ce 49 [2] ba 51 [2] fd 53 [2] ba 42 [2] f4 4e [2] f8 44 [2] ef 4f [2] f4 01 [2] c9 }

  condition:
    any of them
}