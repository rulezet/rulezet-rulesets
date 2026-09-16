rule TTP_XOR_MULT_DOSStub_e4f9 {
  strings:
    $key_e4f9 = { b0 91 [2] c4 89 [2] 83 8b [2] c4 9a [2] 8a 96 [2] 86 9c [2] 91 97 [2] 8a d9 [2] b7 }

  condition:
    any of them
}