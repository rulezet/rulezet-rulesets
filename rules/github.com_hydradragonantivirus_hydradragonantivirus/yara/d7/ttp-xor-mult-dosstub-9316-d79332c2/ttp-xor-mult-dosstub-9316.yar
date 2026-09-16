rule TTP_XOR_MULT_DOSStub_9316 {
  strings:
    $key_9316 = { c7 7e [2] b3 66 [2] f4 64 [2] b3 75 [2] fd 79 [2] f1 73 [2] e6 78 [2] fd 36 [2] c0 }

  condition:
    any of them
}