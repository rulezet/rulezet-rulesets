rule TTP_XOR_MULT_DOSStub_92f4 {
  strings:
    $key_92f4 = { c6 9c [2] b2 84 [2] f5 86 [2] b2 97 [2] fc 9b [2] f0 91 [2] e7 9a [2] fc d4 [2] c1 }

  condition:
    any of them
}