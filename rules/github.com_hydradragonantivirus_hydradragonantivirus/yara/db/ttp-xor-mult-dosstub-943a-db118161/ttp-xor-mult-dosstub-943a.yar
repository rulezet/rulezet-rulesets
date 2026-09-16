rule TTP_XOR_MULT_DOSStub_943a {
  strings:
    $key_943a = { c0 52 [2] b4 4a [2] f3 48 [2] b4 59 [2] fa 55 [2] f6 5f [2] e1 54 [2] fa 1a [2] c7 }

  condition:
    any of them
}