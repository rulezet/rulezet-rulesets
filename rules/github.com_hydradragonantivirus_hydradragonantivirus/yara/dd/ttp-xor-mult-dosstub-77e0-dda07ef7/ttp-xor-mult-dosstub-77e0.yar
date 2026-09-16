rule TTP_XOR_MULT_DOSStub_77e0 {
  strings:
    $key_77e0 = { 23 88 [2] 57 90 [2] 10 92 [2] 57 83 [2] 19 8f [2] 15 85 [2] 02 8e [2] 19 c0 [2] 24 }

  condition:
    any of them
}