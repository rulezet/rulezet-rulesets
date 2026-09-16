rule TTP_XOR_MULT_DOSStub_a15c {
  strings:
    $key_a15c = { f5 34 [2] 81 2c [2] c6 2e [2] 81 3f [2] cf 33 [2] c3 39 [2] d4 32 [2] cf 7c [2] f2 }

  condition:
    any of them
}