rule TTP_XOR_MULT_DOSStub_9313 {
  strings:
    $key_9313 = { c7 7b [2] b3 63 [2] f4 61 [2] b3 70 [2] fd 7c [2] f1 76 [2] e6 7d [2] fd 33 [2] c0 }

  condition:
    any of them
}