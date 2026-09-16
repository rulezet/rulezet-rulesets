rule TTP_XOR_MULT_DOSStub_37e0 {
  strings:
    $key_37e0 = { 63 88 [2] 17 90 [2] 50 92 [2] 17 83 [2] 59 8f [2] 55 85 [2] 42 8e [2] 59 c0 [2] 64 }

  condition:
    any of them
}