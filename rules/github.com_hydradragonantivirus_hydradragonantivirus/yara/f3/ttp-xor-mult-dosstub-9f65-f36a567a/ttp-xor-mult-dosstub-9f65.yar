rule TTP_XOR_MULT_DOSStub_9f65 {
  strings:
    $key_9f65 = { cb 0d [2] bf 15 [2] f8 17 [2] bf 06 [2] f1 0a [2] fd 00 [2] ea 0b [2] f1 45 [2] cc }

  condition:
    any of them
}