rule TTP_XOR_MULT_DOSStub_9ff4 {
  strings:
    $key_9ff4 = { cb 9c [2] bf 84 [2] f8 86 [2] bf 97 [2] f1 9b [2] fd 91 [2] ea 9a [2] f1 d4 [2] cc }

  condition:
    any of them
}