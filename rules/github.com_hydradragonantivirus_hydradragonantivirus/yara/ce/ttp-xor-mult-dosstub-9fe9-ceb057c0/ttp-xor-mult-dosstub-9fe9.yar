rule TTP_XOR_MULT_DOSStub_9fe9 {
  strings:
    $key_9fe9 = { cb 81 [2] bf 99 [2] f8 9b [2] bf 8a [2] f1 86 [2] fd 8c [2] ea 87 [2] f1 c9 [2] cc }

  condition:
    any of them
}