rule TTP_XOR_MULT_DOSStub_a11f {
  strings:
    $key_a11f = { f5 77 [2] 81 6f [2] c6 6d [2] 81 7c [2] cf 70 [2] c3 7a [2] d4 71 [2] cf 3f [2] f2 }

  condition:
    any of them
}