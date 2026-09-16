rule TTP_XOR_MULT_DOSStub_9f48 {
  strings:
    $key_9f48 = { cb 20 [2] bf 38 [2] f8 3a [2] bf 2b [2] f1 27 [2] fd 2d [2] ea 26 [2] f1 68 [2] cc }

  condition:
    any of them
}