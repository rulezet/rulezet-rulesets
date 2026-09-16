rule TTP_XOR_MULT_DOSStub_9a6f {
  strings:
    $key_9a6f = { ce 07 [2] ba 1f [2] fd 1d [2] ba 0c [2] f4 00 [2] f8 0a [2] ef 01 [2] f4 4f [2] c9 }

  condition:
    any of them
}