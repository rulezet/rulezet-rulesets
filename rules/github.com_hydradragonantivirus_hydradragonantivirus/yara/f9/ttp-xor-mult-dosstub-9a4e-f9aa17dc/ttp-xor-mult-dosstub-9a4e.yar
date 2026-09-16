rule TTP_XOR_MULT_DOSStub_9a4e {
  strings:
    $key_9a4e = { ce 26 [2] ba 3e [2] fd 3c [2] ba 2d [2] f4 21 [2] f8 2b [2] ef 20 [2] f4 6e [2] c9 }

  condition:
    any of them
}