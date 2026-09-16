rule TTP_XOR_MULT_DOSStub_979d {
  strings:
    $key_979d = { c3 f5 [2] b7 ed [2] f0 ef [2] b7 fe [2] f9 f2 [2] f5 f8 [2] e2 f3 [2] f9 bd [2] c4 }

  condition:
    any of them
}