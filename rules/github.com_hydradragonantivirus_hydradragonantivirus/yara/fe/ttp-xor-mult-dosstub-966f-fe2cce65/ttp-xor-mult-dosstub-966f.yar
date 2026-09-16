rule TTP_XOR_MULT_DOSStub_966f {
  strings:
    $key_966f = { c2 07 [2] b6 1f [2] f1 1d [2] b6 0c [2] f8 00 [2] f4 0a [2] e3 01 [2] f8 4f [2] c5 }

  condition:
    any of them
}