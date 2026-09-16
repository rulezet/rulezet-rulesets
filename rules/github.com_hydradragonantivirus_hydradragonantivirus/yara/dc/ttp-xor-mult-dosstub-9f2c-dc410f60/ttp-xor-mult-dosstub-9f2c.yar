rule TTP_XOR_MULT_DOSStub_9f2c {
  strings:
    $key_9f2c = { cb 44 [2] bf 5c [2] f8 5e [2] bf 4f [2] f1 43 [2] fd 49 [2] ea 42 [2] f1 0c [2] cc }

  condition:
    any of them
}