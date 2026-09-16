rule TTP_XOR_MULT_DOSStub_91e2 {
  strings:
    $key_91e2 = { c5 8a [2] b1 92 [2] f6 90 [2] b1 81 [2] ff 8d [2] f3 87 [2] e4 8c [2] ff c2 [2] c2 }

  condition:
    any of them
}