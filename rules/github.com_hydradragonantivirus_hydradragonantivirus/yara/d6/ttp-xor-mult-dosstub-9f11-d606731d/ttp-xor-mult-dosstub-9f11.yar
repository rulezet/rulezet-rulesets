rule TTP_XOR_MULT_DOSStub_9f11 {
  strings:
    $key_9f11 = { cb 79 [2] bf 61 [2] f8 63 [2] bf 72 [2] f1 7e [2] fd 74 [2] ea 7f [2] f1 31 [2] cc }

  condition:
    any of them
}