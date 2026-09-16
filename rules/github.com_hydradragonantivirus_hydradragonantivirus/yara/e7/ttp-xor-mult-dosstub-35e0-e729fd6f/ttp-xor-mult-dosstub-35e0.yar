rule TTP_XOR_MULT_DOSStub_35e0 {
  strings:
    $key_35e0 = { 61 88 [2] 15 90 [2] 52 92 [2] 15 83 [2] 5b 8f [2] 57 85 [2] 40 8e [2] 5b c0 [2] 66 }

  condition:
    any of them
}