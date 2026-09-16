rule TTP_XOR_MULT_DOSStub_a110 {
  strings:
    $key_a110 = { f5 78 [2] 81 60 [2] c6 62 [2] 81 73 [2] cf 7f [2] c3 75 [2] d4 7e [2] cf 30 [2] f2 }

  condition:
    any of them
}