rule TTP_XOR_MULT_DOSStub_9fef {
  strings:
    $key_9fef = { cb 87 [2] bf 9f [2] f8 9d [2] bf 8c [2] f1 80 [2] fd 8a [2] ea 81 [2] f1 cf [2] cc }

  condition:
    any of them
}