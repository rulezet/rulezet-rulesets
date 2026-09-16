rule TTP_XOR_MULT_DOSStub_9a75 {
  strings:
    $key_9a75 = { ce 1d [2] ba 05 [2] fd 07 [2] ba 16 [2] f4 1a [2] f8 10 [2] ef 1b [2] f4 55 [2] c9 }

  condition:
    any of them
}