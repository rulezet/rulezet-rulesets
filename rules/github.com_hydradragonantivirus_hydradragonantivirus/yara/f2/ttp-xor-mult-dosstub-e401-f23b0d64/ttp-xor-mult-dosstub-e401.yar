rule TTP_XOR_MULT_DOSStub_e401 {
  strings:
    $key_e401 = { b0 69 [2] c4 71 [2] 83 73 [2] c4 62 [2] 8a 6e [2] 86 64 [2] 91 6f [2] 8a 21 [2] b7 }

  condition:
    any of them
}