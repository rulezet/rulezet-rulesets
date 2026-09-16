rule TTP_XOR_MULT_DOSStub_a7e5 {
  strings:
    $key_a7e5 = { f3 8d [2] 87 95 [2] c0 97 [2] 87 86 [2] c9 8a [2] c5 80 [2] d2 8b [2] c9 c5 [2] f4 }

  condition:
    any of them
}