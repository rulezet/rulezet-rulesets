rule TTP_XOR_MULT_DOSStub_9525 {
  strings:
    $key_9525 = { c1 4d [2] b5 55 [2] f2 57 [2] b5 46 [2] fb 4a [2] f7 40 [2] e0 4b [2] fb 05 [2] c6 }

  condition:
    any of them
}