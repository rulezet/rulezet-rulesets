rule TTP_XOR_MULT_DOSStub_e4e5 {
  strings:
    $key_e4e5 = { b0 8d [2] c4 95 [2] 83 97 [2] c4 86 [2] 8a 8a [2] 86 80 [2] 91 8b [2] 8a c5 [2] b7 }

  condition:
    any of them
}