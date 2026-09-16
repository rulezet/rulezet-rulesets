rule TTP_XOR_MULT_DOSStub_9a19 {
  strings:
    $key_9a19 = { ce 71 [2] ba 69 [2] fd 6b [2] ba 7a [2] f4 76 [2] f8 7c [2] ef 77 [2] f4 39 [2] c9 }

  condition:
    any of them
}