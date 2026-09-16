rule TTP_XOR_MULT_DOSStub_9ff2 {
  strings:
    $key_9ff2 = { cb 9a [2] bf 82 [2] f8 80 [2] bf 91 [2] f1 9d [2] fd 97 [2] ea 9c [2] f1 d2 [2] cc }

  condition:
    any of them
}