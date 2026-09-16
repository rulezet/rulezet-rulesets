rule TTP_XOR_MULT_DOSStub_9f28 {
  strings:
    $key_9f28 = { cb 40 [2] bf 58 [2] f8 5a [2] bf 4b [2] f1 47 [2] fd 4d [2] ea 46 [2] f1 08 [2] cc }

  condition:
    any of them
}