rule TTP_XOR_MULT_DOSStub_9f1e {
  strings:
    $key_9f1e = { cb 76 [2] bf 6e [2] f8 6c [2] bf 7d [2] f1 71 [2] fd 7b [2] ea 70 [2] f1 3e [2] cc }

  condition:
    any of them
}