rule TTP_XOR_MULT_DOSStub_e541 {
  strings:
    $key_e541 = { b1 29 [2] c5 31 [2] 82 33 [2] c5 22 [2] 8b 2e [2] 87 24 [2] 90 2f [2] 8b 61 [2] b6 }

  condition:
    any of them
}