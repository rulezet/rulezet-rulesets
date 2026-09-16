rule TTP_XOR_MULT_DOSStub_9fe6 {
  strings:
    $key_9fe6 = { cb 8e [2] bf 96 [2] f8 94 [2] bf 85 [2] f1 89 [2] fd 83 [2] ea 88 [2] f1 c6 [2] cc }

  condition:
    any of them
}