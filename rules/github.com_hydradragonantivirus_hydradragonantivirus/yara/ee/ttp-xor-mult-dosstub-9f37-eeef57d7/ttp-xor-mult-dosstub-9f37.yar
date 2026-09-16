rule TTP_XOR_MULT_DOSStub_9f37 {
  strings:
    $key_9f37 = { cb 5f [2] bf 47 [2] f8 45 [2] bf 54 [2] f1 58 [2] fd 52 [2] ea 59 [2] f1 17 [2] cc }

  condition:
    any of them
}