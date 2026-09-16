rule TTP_XOR_MULT_DOSStub_90f4 {
  strings:
    $key_90f4 = { c4 9c [2] b0 84 [2] f7 86 [2] b0 97 [2] fe 9b [2] f2 91 [2] e5 9a [2] fe d4 [2] c3 }

  condition:
    any of them
}