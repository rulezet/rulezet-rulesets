rule TTP_XOR_MULT_DOSStub_9362 {
  strings:
    $key_9362 = { c7 0a [2] b3 12 [2] f4 10 [2] b3 01 [2] fd 0d [2] f1 07 [2] e6 0c [2] fd 42 [2] c0 }

  condition:
    any of them
}