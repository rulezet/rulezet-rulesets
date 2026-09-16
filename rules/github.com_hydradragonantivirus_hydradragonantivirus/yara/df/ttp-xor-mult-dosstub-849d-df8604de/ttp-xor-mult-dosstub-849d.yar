rule TTP_XOR_MULT_DOSStub_849d {
  strings:
    $key_849d = { d0 f5 [2] a4 ed [2] e3 ef [2] a4 fe [2] ea f2 [2] e6 f8 [2] f1 f3 [2] ea bd [2] d7 }

  condition:
    any of them
}