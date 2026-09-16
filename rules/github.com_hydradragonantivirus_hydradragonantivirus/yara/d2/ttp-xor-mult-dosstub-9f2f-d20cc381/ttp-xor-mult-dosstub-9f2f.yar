rule TTP_XOR_MULT_DOSStub_9f2f {
  strings:
    $key_9f2f = { cb 47 [2] bf 5f [2] f8 5d [2] bf 4c [2] f1 40 [2] fd 4a [2] ea 41 [2] f1 0f [2] cc }

  condition:
    any of them
}