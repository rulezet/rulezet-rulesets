rule TTP_XOR_MULT_DOSStub_20e0 {
  strings:
    $key_20e0 = { 74 88 [2] 00 90 [2] 47 92 [2] 00 83 [2] 4e 8f [2] 42 85 [2] 55 8e [2] 4e c0 [2] 73 }

  condition:
    any of them
}