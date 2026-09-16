rule TTP_XOR_MULT_DOSStub_843a {
  strings:
    $key_843a = { d0 52 [2] a4 4a [2] e3 48 [2] a4 59 [2] ea 55 [2] e6 5f [2] f1 54 [2] ea 1a [2] d7 }

  condition:
    any of them
}