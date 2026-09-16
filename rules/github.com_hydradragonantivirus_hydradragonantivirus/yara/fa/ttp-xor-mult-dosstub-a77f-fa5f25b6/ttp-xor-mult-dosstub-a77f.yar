rule TTP_XOR_MULT_DOSStub_a77f {
  strings:
    $key_a77f = { f3 17 [2] 87 0f [2] c0 0d [2] 87 1c [2] c9 10 [2] c5 1a [2] d2 11 [2] c9 5f [2] f4 }

  condition:
    any of them
}