rule TTP_XOR_MULT_DOSStub_9a20 {
  strings:
    $key_9a20 = { ce 48 [2] ba 50 [2] fd 52 [2] ba 43 [2] f4 4f [2] f8 45 [2] ef 4e [2] f4 00 [2] c9 }

  condition:
    any of them
}