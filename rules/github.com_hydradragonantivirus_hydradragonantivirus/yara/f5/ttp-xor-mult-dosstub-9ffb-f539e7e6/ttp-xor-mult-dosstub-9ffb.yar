rule TTP_XOR_MULT_DOSStub_9ffb {
  strings:
    $key_9ffb = { cb 93 [2] bf 8b [2] f8 89 [2] bf 98 [2] f1 94 [2] fd 9e [2] ea 95 [2] f1 db [2] cc }

  condition:
    any of them
}