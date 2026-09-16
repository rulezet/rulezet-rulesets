rule TTP_XOR_MULT_DOSStub_9f27 {
  strings:
    $key_9f27 = { cb 4f [2] bf 57 [2] f8 55 [2] bf 44 [2] f1 48 [2] fd 42 [2] ea 49 [2] f1 07 [2] cc }

  condition:
    any of them
}