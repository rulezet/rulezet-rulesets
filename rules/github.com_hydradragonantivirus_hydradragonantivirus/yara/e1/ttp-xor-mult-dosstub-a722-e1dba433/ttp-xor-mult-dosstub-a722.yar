rule TTP_XOR_MULT_DOSStub_a722 {
  strings:
    $key_a722 = { f3 4a [2] 87 52 [2] c0 50 [2] 87 41 [2] c9 4d [2] c5 47 [2] d2 4c [2] c9 02 [2] f4 }

  condition:
    any of them
}