rule TTP_XOR_MULT_DOSStub_91e8 {
  strings:
    $key_91e8 = { c5 80 [2] b1 98 [2] f6 9a [2] b1 8b [2] ff 87 [2] f3 8d [2] e4 86 [2] ff c8 [2] c2 }

  condition:
    any of them
}