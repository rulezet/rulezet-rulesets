rule TTP_XOR_MULT_DOSStub_977f {
  strings:
    $key_977f = { c3 17 [2] b7 0f [2] f0 0d [2] b7 1c [2] f9 10 [2] f5 1a [2] e2 11 [2] f9 5f [2] c4 }

  condition:
    any of them
}