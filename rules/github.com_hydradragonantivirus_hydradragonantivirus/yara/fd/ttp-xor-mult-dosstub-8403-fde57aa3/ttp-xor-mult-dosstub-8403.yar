rule TTP_XOR_MULT_DOSStub_8403 {
  strings:
    $key_8403 = { d0 6b [2] a4 73 [2] e3 71 [2] a4 60 [2] ea 6c [2] e6 66 [2] f1 6d [2] ea 23 [2] d7 }

  condition:
    any of them
}