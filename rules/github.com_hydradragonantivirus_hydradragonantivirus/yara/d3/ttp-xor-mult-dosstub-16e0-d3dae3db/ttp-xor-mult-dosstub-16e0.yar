rule TTP_XOR_MULT_DOSStub_16e0 {
  strings:
    $key_16e0 = { 42 88 [2] 36 90 [2] 71 92 [2] 36 83 [2] 78 8f [2] 74 85 [2] 63 8e [2] 78 c0 [2] 45 }

  condition:
    any of them
}