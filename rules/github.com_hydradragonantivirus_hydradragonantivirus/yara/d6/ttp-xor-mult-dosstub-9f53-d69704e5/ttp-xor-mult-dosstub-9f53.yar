rule TTP_XOR_MULT_DOSStub_9f53 {
  strings:
    $key_9f53 = { cb 3b [2] bf 23 [2] f8 21 [2] bf 30 [2] f1 3c [2] fd 36 [2] ea 3d [2] f1 73 [2] cc }

  condition:
    any of them
}