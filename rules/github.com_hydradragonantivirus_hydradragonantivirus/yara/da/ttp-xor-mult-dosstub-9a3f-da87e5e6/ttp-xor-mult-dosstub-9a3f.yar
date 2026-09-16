rule TTP_XOR_MULT_DOSStub_9a3f {
  strings:
    $key_9a3f = { ce 57 [2] ba 4f [2] fd 4d [2] ba 5c [2] f4 50 [2] f8 5a [2] ef 51 [2] f4 1f [2] c9 }

  condition:
    any of them
}