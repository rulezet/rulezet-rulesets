rule TTP_XOR_MULT_DOSStub_9a4c {
  strings:
    $key_9a4c = { ce 24 [2] ba 3c [2] fd 3e [2] ba 2f [2] f4 23 [2] f8 29 [2] ef 22 [2] f4 6c [2] c9 }

  condition:
    any of them
}