rule TTP_XOR_MULT_DOSStub_9aec {
  strings:
    $key_9aec = { ce 84 [2] ba 9c [2] fd 9e [2] ba 8f [2] f4 83 [2] f8 89 [2] ef 82 [2] f4 cc [2] c9 }

  condition:
    any of them
}