rule TTP_XOR_MULT_DOSStub_e451 {
  strings:
    $key_e451 = { b0 39 [2] c4 21 [2] 83 23 [2] c4 32 [2] 8a 3e [2] 86 34 [2] 91 3f [2] 8a 71 [2] b7 }

  condition:
    any of them
}