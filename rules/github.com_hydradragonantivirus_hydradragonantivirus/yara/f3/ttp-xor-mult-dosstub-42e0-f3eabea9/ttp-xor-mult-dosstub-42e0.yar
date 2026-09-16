rule TTP_XOR_MULT_DOSStub_42e0 {
  strings:
    $key_42e0 = { 16 88 [2] 62 90 [2] 25 92 [2] 62 83 [2] 2c 8f [2] 20 85 [2] 37 8e [2] 2c c0 [2] 11 }

  condition:
    any of them
}