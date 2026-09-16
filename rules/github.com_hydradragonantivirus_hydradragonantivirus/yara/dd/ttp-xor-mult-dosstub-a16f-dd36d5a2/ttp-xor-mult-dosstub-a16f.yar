rule TTP_XOR_MULT_DOSStub_a16f {
  strings:
    $key_a16f = { f5 07 [2] 81 1f [2] c6 1d [2] 81 0c [2] cf 00 [2] c3 0a [2] d4 01 [2] cf 4f [2] f2 }

  condition:
    any of them
}