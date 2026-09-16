rule TTP_XOR_MULT_DOSStub_9329 {
  strings:
    $key_9329 = { c7 41 [2] b3 59 [2] f4 5b [2] b3 4a [2] fd 46 [2] f1 4c [2] e6 47 [2] fd 09 [2] c0 }

  condition:
    any of them
}