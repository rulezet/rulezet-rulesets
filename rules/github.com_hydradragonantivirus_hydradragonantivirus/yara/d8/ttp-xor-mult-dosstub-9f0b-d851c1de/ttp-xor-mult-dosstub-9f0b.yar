rule TTP_XOR_MULT_DOSStub_9f0b {
  strings:
    $key_9f0b = { cb 63 [2] bf 7b [2] f8 79 [2] bf 68 [2] f1 64 [2] fd 6e [2] ea 65 [2] f1 2b [2] cc }

  condition:
    any of them
}