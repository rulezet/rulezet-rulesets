rule TTP_XOR_MULT_DOSStub_9f1a {
  strings:
    $key_9f1a = { cb 72 [2] bf 6a [2] f8 68 [2] bf 79 [2] f1 75 [2] fd 7f [2] ea 74 [2] f1 3a [2] cc }

  condition:
    any of them
}