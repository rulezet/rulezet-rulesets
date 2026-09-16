rule TTP_XOR_MULT_DOSStub_9324 {
  strings:
    $key_9324 = { c7 4c [2] b3 54 [2] f4 56 [2] b3 47 [2] fd 4b [2] f1 41 [2] e6 4a [2] fd 04 [2] c0 }

  condition:
    any of them
}