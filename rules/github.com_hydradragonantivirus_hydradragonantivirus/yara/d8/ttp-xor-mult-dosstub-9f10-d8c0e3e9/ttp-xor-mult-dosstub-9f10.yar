rule TTP_XOR_MULT_DOSStub_9f10 {
  strings:
    $key_9f10 = { cb 78 [2] bf 60 [2] f8 62 [2] bf 73 [2] f1 7f [2] fd 75 [2] ea 7e [2] f1 30 [2] cc }

  condition:
    any of them
}