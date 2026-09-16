rule TTP_XOR_MULT_DOSStub_a122 {
  strings:
    $key_a122 = { f5 4a [2] 81 52 [2] c6 50 [2] 81 41 [2] cf 4d [2] c3 47 [2] d4 4c [2] cf 02 [2] f2 }

  condition:
    any of them
}