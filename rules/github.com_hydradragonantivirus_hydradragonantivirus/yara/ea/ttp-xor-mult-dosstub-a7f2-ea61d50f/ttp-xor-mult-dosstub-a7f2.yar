rule TTP_XOR_MULT_DOSStub_a7f2 {
  strings:
    $key_a7f2 = { f3 9a [2] 87 82 [2] c0 80 [2] 87 91 [2] c9 9d [2] c5 97 [2] d2 9c [2] c9 d2 [2] f4 }

  condition:
    any of them
}