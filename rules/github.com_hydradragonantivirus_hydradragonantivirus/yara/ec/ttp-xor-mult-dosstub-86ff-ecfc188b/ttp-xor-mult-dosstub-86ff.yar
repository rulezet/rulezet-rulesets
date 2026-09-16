rule TTP_XOR_MULT_DOSStub_86ff {
  strings:
    $key_86ff = { d2 97 [2] a6 8f [2] e1 8d [2] a6 9c [2] e8 90 [2] e4 9a [2] f3 91 [2] e8 df [2] d5 }

  condition:
    any of them
}