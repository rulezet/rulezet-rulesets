rule TTP_XOR_MULT_DOSStub_9725 {
  strings:
    $key_9725 = { c3 4d [2] b7 55 [2] f0 57 [2] b7 46 [2] f9 4a [2] f5 40 [2] e2 4b [2] f9 05 [2] c4 }

  condition:
    any of them
}