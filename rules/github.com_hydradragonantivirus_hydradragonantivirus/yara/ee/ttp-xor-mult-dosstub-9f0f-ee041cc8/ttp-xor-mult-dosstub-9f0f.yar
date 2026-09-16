rule TTP_XOR_MULT_DOSStub_9f0f {
  strings:
    $key_9f0f = { cb 67 [2] bf 7f [2] f8 7d [2] bf 6c [2] f1 60 [2] fd 6a [2] ea 61 [2] f1 2f [2] cc }

  condition:
    any of them
}