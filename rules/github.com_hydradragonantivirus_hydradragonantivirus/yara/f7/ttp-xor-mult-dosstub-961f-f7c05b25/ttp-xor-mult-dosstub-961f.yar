rule TTP_XOR_MULT_DOSStub_961f {
  strings:
    $key_961f = { c2 77 [2] b6 6f [2] f1 6d [2] b6 7c [2] f8 70 [2] f4 7a [2] e3 71 [2] f8 3f [2] c5 }

  condition:
    any of them
}