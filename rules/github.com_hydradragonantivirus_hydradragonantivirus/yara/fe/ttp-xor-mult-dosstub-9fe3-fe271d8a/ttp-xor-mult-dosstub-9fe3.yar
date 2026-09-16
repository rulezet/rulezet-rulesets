rule TTP_XOR_MULT_DOSStub_9fe3 {
  strings:
    $key_9fe3 = { cb 8b [2] bf 93 [2] f8 91 [2] bf 80 [2] f1 8c [2] fd 86 [2] ea 8d [2] f1 c3 [2] cc }

  condition:
    any of them
}