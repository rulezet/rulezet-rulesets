rule TTP_XOR_MULT_DOSStub_9f74 {
  strings:
    $key_9f74 = { cb 1c [2] bf 04 [2] f8 06 [2] bf 17 [2] f1 1b [2] fd 11 [2] ea 1a [2] f1 54 [2] cc }

  condition:
    any of them
}