rule TTP_XOR_MULT_DOSStub_40e0 {
  strings:
    $key_40e0 = { 14 88 [2] 60 90 [2] 27 92 [2] 60 83 [2] 2e 8f [2] 22 85 [2] 35 8e [2] 2e c0 [2] 13 }

  condition:
    any of them
}