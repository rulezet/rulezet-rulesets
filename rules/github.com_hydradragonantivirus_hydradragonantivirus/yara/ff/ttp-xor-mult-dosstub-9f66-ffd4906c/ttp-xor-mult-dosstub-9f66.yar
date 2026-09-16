rule TTP_XOR_MULT_DOSStub_9f66 {
  strings:
    $key_9f66 = { cb 0e [2] bf 16 [2] f8 14 [2] bf 05 [2] f1 09 [2] fd 03 [2] ea 08 [2] f1 46 [2] cc }

  condition:
    any of them
}