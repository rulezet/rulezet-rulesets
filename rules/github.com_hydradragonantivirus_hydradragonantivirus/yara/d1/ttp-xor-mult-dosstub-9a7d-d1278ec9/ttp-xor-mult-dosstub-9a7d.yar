rule TTP_XOR_MULT_DOSStub_9a7d {
  strings:
    $key_9a7d = { ce 15 [2] ba 0d [2] fd 0f [2] ba 1e [2] f4 12 [2] f8 18 [2] ef 13 [2] f4 5d [2] c9 }

  condition:
    any of them
}