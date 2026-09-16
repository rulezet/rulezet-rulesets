rule TTP_XOR_MULT_DOSStub_56e0 {
  strings:
    $key_56e0 = { 02 88 [2] 76 90 [2] 31 92 [2] 76 83 [2] 38 8f [2] 34 85 [2] 23 8e [2] 38 c0 [2] 05 }

  condition:
    any of them
}