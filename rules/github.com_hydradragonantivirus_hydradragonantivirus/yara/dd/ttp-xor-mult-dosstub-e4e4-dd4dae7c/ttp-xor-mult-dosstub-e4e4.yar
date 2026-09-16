rule TTP_XOR_MULT_DOSStub_e4e4 {
  strings:
    $key_e4e4 = { b0 8c [2] c4 94 [2] 83 96 [2] c4 87 [2] 8a 8b [2] 86 81 [2] 91 8a [2] 8a c4 [2] b7 }

  condition:
    any of them
}