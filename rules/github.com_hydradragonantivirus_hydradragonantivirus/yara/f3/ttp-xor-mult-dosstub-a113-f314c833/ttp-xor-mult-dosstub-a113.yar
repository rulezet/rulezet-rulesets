rule TTP_XOR_MULT_DOSStub_a113 {
  strings:
    $key_a113 = { f5 7b [2] 81 63 [2] c6 61 [2] 81 70 [2] cf 7c [2] c3 76 [2] d4 7d [2] cf 33 [2] f2 }

  condition:
    any of them
}