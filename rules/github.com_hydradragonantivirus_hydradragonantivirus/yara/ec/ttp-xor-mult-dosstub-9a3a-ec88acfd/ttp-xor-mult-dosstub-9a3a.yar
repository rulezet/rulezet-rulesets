rule TTP_XOR_MULT_DOSStub_9a3a {
  strings:
    $key_9a3a = { ce 52 [2] ba 4a [2] fd 48 [2] ba 59 [2] f4 55 [2] f8 5f [2] ef 54 [2] f4 1a [2] c9 }

  condition:
    any of them
}