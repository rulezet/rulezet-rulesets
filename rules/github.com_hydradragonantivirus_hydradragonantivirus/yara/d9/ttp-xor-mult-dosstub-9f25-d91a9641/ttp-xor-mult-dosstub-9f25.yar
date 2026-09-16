rule TTP_XOR_MULT_DOSStub_9f25 {
  strings:
    $key_9f25 = { cb 4d [2] bf 55 [2] f8 57 [2] bf 46 [2] f1 4a [2] fd 40 [2] ea 4b [2] f1 05 [2] cc }

  condition:
    any of them
}