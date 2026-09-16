rule TTP_XOR_MULT_DOSStub_e4f5 {
  strings:
    $key_e4f5 = { b0 9d [2] c4 85 [2] 83 87 [2] c4 96 [2] 8a 9a [2] 86 90 [2] 91 9b [2] 8a d5 [2] b7 }

  condition:
    any of them
}