rule TTP_XOR_MULT_DOSStub_9a29 {
  strings:
    $key_9a29 = { ce 41 [2] ba 59 [2] fd 5b [2] ba 4a [2] f4 46 [2] f8 4c [2] ef 47 [2] f4 09 [2] c9 }

  condition:
    any of them
}