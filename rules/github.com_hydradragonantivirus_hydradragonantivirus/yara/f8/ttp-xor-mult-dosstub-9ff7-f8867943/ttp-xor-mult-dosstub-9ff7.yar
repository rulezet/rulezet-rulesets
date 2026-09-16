rule TTP_XOR_MULT_DOSStub_9ff7 {
  strings:
    $key_9ff7 = { cb 9f [2] bf 87 [2] f8 85 [2] bf 94 [2] f1 98 [2] fd 92 [2] ea 99 [2] f1 d7 [2] cc }

  condition:
    any of them
}