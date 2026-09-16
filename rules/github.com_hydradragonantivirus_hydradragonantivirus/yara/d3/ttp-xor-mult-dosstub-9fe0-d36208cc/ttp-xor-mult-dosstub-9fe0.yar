rule TTP_XOR_MULT_DOSStub_9fe0 {
  strings:
    $key_9fe0 = { cb 88 [2] bf 90 [2] f8 92 [2] bf 83 [2] f1 8f [2] fd 85 [2] ea 8e [2] f1 c0 [2] cc }

  condition:
    any of them
}