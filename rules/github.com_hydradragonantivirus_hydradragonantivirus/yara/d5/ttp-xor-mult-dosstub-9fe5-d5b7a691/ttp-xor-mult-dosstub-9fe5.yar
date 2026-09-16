rule TTP_XOR_MULT_DOSStub_9fe5 {
  strings:
    $key_9fe5 = { cb 8d [2] bf 95 [2] f8 97 [2] bf 86 [2] f1 8a [2] fd 80 [2] ea 8b [2] f1 c5 [2] cc }

  condition:
    any of them
}