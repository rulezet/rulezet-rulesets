rule TTP_XOR_MULT_DOSStub_9f47 {
  strings:
    $key_9f47 = { cb 2f [2] bf 37 [2] f8 35 [2] bf 24 [2] f1 28 [2] fd 22 [2] ea 29 [2] f1 67 [2] cc }

  condition:
    any of them
}