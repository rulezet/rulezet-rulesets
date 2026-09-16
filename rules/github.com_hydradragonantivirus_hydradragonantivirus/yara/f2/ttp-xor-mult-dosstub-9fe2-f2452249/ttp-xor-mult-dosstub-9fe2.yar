rule TTP_XOR_MULT_DOSStub_9fe2 {
  strings:
    $key_9fe2 = { cb 8a [2] bf 92 [2] f8 90 [2] bf 81 [2] f1 8d [2] fd 87 [2] ea 8c [2] f1 c2 [2] cc }

  condition:
    any of them
}