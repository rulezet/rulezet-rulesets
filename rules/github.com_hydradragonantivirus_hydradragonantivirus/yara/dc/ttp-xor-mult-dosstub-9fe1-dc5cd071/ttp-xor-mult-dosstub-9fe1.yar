rule TTP_XOR_MULT_DOSStub_9fe1 {
  strings:
    $key_9fe1 = { cb 89 [2] bf 91 [2] f8 93 [2] bf 82 [2] f1 8e [2] fd 84 [2] ea 8f [2] f1 c1 [2] cc }

  condition:
    any of them
}