rule TTP_XOR_MULT_DOSStub_9f70 {
  strings:
    $key_9f70 = { cb 18 [2] bf 00 [2] f8 02 [2] bf 13 [2] f1 1f [2] fd 15 [2] ea 1e [2] f1 50 [2] cc }

  condition:
    any of them
}