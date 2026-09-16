rule TTP_XOR_MULT_DOSStub_9a60 {
  strings:
    $key_9a60 = { ce 08 [2] ba 10 [2] fd 12 [2] ba 03 [2] f4 0f [2] f8 05 [2] ef 0e [2] f4 40 [2] c9 }

  condition:
    any of them
}