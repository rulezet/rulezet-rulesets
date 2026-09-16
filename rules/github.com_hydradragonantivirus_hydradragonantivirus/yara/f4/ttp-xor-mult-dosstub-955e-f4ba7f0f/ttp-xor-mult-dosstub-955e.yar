rule TTP_XOR_MULT_DOSStub_955e {
  strings:
    $key_955e = { c1 36 [2] b5 2e [2] f2 2c [2] b5 3d [2] fb 31 [2] f7 3b [2] e0 30 [2] fb 7e [2] c6 }

  condition:
    any of them
}