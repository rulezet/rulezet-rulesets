rule TTP_XOR_MULT_DOSStub_9fc6 {
  strings:
    $key_9fc6 = { cb ae [2] bf b6 [2] f8 b4 [2] bf a5 [2] f1 a9 [2] fd a3 [2] ea a8 [2] f1 e6 [2] cc }

  condition:
    any of them
}