rule TTP_XOR_MULT_DOSStub_9303 {
  strings:
    $key_9303 = { c7 6b [2] b3 73 [2] f4 71 [2] b3 60 [2] fd 6c [2] f1 66 [2] e6 6d [2] fd 23 [2] c0 }

  condition:
    any of them
}