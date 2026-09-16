rule TTP_XOR_MULT_DOSStub_91f0 {
  strings:
    $key_91f0 = { c5 98 [2] b1 80 [2] f6 82 [2] b1 93 [2] ff 9f [2] f3 95 [2] e4 9e [2] ff d0 [2] c2 }

  condition:
    any of them
}