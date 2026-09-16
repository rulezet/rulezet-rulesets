rule TTP_XOR_MULT_DOSStub_9a1e {
  strings:
    $key_9a1e = { ce 76 [2] ba 6e [2] fd 6c [2] ba 7d [2] f4 71 [2] f8 7b [2] ef 70 [2] f4 3e [2] c9 }

  condition:
    any of them
}