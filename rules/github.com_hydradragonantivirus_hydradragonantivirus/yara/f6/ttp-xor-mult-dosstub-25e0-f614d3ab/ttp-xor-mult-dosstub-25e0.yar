rule TTP_XOR_MULT_DOSStub_25e0 {
  strings:
    $key_25e0 = { 71 88 [2] 05 90 [2] 42 92 [2] 05 83 [2] 4b 8f [2] 47 85 [2] 50 8e [2] 4b c0 [2] 76 }

  condition:
    any of them
}