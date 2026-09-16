rule TTP_XOR_MULT_DOSStub_9f52 {
  strings:
    $key_9f52 = { cb 3a [2] bf 22 [2] f8 20 [2] bf 31 [2] f1 3d [2] fd 37 [2] ea 3c [2] f1 72 [2] cc }

  condition:
    any of them
}