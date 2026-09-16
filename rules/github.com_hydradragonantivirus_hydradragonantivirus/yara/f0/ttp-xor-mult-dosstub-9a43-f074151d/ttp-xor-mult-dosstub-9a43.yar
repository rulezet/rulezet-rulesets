rule TTP_XOR_MULT_DOSStub_9a43 {
  strings:
    $key_9a43 = { ce 2b [2] ba 33 [2] fd 31 [2] ba 20 [2] f4 2c [2] f8 26 [2] ef 2d [2] f4 63 [2] c9 }

  condition:
    any of them
}