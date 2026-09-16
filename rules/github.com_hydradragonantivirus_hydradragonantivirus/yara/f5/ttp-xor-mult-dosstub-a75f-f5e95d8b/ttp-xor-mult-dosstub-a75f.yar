rule TTP_XOR_MULT_DOSStub_a75f {
  strings:
    $key_a75f = { f3 37 [2] 87 2f [2] c0 2d [2] 87 3c [2] c9 30 [2] c5 3a [2] d2 31 [2] c9 7f [2] f4 }

  condition:
    any of them
}