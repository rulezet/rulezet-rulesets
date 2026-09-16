rule TTP_XOR_MULT_DOSStub_9328 {
  strings:
    $key_9328 = { c7 40 [2] b3 58 [2] f4 5a [2] b3 4b [2] fd 47 [2] f1 4d [2] e6 46 [2] fd 08 [2] c0 }

  condition:
    any of them
}