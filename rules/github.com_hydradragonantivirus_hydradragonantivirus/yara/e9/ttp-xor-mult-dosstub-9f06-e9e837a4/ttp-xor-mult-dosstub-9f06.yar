rule TTP_XOR_MULT_DOSStub_9f06 {
  strings:
    $key_9f06 = { cb 6e [2] bf 76 [2] f8 74 [2] bf 65 [2] f1 69 [2] fd 63 [2] ea 68 [2] f1 26 [2] cc }

  condition:
    any of them
}