rule TTP_XOR_MULT_DOSStub_e556 {
  strings:
    $key_e556 = { b1 3e [2] c5 26 [2] 82 24 [2] c5 35 [2] 8b 39 [2] 87 33 [2] 90 38 [2] 8b 76 [2] b6 }

  condition:
    any of them
}