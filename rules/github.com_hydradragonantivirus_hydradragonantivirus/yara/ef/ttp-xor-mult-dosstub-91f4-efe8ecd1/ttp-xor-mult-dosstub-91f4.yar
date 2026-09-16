rule TTP_XOR_MULT_DOSStub_91f4 {
  strings:
    $key_91f4 = { c5 9c [2] b1 84 [2] f6 86 [2] b1 97 [2] ff 9b [2] f3 91 [2] e4 9a [2] ff d4 [2] c2 }

  condition:
    any of them
}