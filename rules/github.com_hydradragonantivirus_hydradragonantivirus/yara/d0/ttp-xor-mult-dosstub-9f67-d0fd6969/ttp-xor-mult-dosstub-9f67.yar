rule TTP_XOR_MULT_DOSStub_9f67 {
  strings:
    $key_9f67 = { cb 0f [2] bf 17 [2] f8 15 [2] bf 04 [2] f1 08 [2] fd 02 [2] ea 09 [2] f1 47 [2] cc }

  condition:
    any of them
}