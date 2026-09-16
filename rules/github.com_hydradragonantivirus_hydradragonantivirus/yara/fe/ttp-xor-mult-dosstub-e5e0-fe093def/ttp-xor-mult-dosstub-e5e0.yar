rule TTP_XOR_MULT_DOSStub_e5e0 {
  strings:
    $key_e5e0 = { b1 88 [2] c5 90 [2] 82 92 [2] c5 83 [2] 8b 8f [2] 87 85 [2] 90 8e [2] 8b c0 [2] b6 }

  condition:
    any of them
}