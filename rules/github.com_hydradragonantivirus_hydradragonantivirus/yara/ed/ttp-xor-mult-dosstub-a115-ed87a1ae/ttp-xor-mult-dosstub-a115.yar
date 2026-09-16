rule TTP_XOR_MULT_DOSStub_a115 {
  strings:
    $key_a115 = { f5 7d [2] 81 65 [2] c6 67 [2] 81 76 [2] cf 7a [2] c3 70 [2] d4 7b [2] cf 35 [2] f2 }

  condition:
    any of them
}