rule TTP_XOR_MULT_DOSStub_9f6f {
  strings:
    $key_9f6f = { cb 07 [2] bf 1f [2] f8 1d [2] bf 0c [2] f1 00 [2] fd 0a [2] ea 01 [2] f1 4f [2] cc }

  condition:
    any of them
}