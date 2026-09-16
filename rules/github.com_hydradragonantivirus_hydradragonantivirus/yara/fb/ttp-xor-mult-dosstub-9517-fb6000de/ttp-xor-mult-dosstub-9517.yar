rule TTP_XOR_MULT_DOSStub_9517 {
  strings:
    $key_9517 = { c1 7f [2] b5 67 [2] f2 65 [2] b5 74 [2] fb 78 [2] f7 72 [2] e0 79 [2] fb 37 [2] c6 }

  condition:
    any of them
}