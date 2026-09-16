rule TTP_XOR_MULT_DOSStub_9f79 {
  strings:
    $key_9f79 = { cb 11 [2] bf 09 [2] f8 0b [2] bf 1a [2] f1 16 [2] fd 1c [2] ea 17 [2] f1 59 [2] cc }

  condition:
    any of them
}