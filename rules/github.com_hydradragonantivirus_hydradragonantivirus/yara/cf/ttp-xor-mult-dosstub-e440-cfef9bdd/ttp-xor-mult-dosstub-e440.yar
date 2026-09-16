rule TTP_XOR_MULT_DOSStub_e440 {
  strings:
    $key_e440 = { b0 28 [2] c4 30 [2] 83 32 [2] c4 23 [2] 8a 2f [2] 86 25 [2] 91 2e [2] 8a 60 [2] b7 }

  condition:
    any of them
}