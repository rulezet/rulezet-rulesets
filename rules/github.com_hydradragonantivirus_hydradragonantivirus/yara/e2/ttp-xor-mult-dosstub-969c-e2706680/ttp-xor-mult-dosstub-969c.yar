rule TTP_XOR_MULT_DOSStub_969c {
  strings:
    $key_969c = { c2 f4 [2] b6 ec [2] f1 ee [2] b6 ff [2] f8 f3 [2] f4 f9 [2] e3 f2 [2] f8 bc [2] c5 }

  condition:
    any of them
}