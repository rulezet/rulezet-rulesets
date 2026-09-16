rule TTP_XOR_MULT_DOSStub_9a5a {
  strings:
    $key_9a5a = { ce 32 [2] ba 2a [2] fd 28 [2] ba 39 [2] f4 35 [2] f8 3f [2] ef 34 [2] f4 7a [2] c9 }

  condition:
    any of them
}