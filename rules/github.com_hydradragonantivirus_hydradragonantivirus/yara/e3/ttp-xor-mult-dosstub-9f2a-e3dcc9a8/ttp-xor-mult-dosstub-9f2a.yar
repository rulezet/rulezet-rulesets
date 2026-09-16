rule TTP_XOR_MULT_DOSStub_9f2a {
  strings:
    $key_9f2a = { cb 42 [2] bf 5a [2] f8 58 [2] bf 49 [2] f1 45 [2] fd 4f [2] ea 44 [2] f1 0a [2] cc }

  condition:
    any of them
}