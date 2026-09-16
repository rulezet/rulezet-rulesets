rule TTP_XOR_MULT_DOSStub_a7f4 {
  strings:
    $key_a7f4 = { f3 9c [2] 87 84 [2] c0 86 [2] 87 97 [2] c9 9b [2] c5 91 [2] d2 9a [2] c9 d4 [2] f4 }

  condition:
    any of them
}