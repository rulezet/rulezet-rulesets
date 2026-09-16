rule TTP_XOR_MULT_DOSStub_e417 {
  strings:
    $key_e417 = { b0 7f [2] c4 67 [2] 83 65 [2] c4 74 [2] 8a 78 [2] 86 72 [2] 91 79 [2] 8a 37 [2] b7 }

  condition:
    any of them
}