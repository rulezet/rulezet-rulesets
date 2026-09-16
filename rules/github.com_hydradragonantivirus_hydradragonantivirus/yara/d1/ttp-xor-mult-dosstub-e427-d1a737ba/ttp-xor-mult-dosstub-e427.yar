rule TTP_XOR_MULT_DOSStub_e427 {
  strings:
    $key_e427 = { b0 4f [2] c4 57 [2] 83 55 [2] c4 44 [2] 8a 48 [2] 86 42 [2] 91 49 [2] 8a 07 [2] b7 }

  condition:
    any of them
}