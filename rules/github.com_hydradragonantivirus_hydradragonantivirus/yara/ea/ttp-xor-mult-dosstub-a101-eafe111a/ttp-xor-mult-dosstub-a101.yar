rule TTP_XOR_MULT_DOSStub_a101 {
  strings:
    $key_a101 = { f5 69 [2] 81 71 [2] c6 73 [2] 81 62 [2] cf 6e [2] c3 64 [2] d4 6f [2] cf 21 [2] f2 }

  condition:
    any of them
}