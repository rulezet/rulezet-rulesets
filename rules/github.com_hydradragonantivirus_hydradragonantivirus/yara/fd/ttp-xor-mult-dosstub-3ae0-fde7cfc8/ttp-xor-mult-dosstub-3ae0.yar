rule TTP_XOR_MULT_DOSStub_3ae0 {
  strings:
    $key_3ae0 = { 6e 88 [2] 1a 90 [2] 5d 92 [2] 1a 83 [2] 54 8f [2] 58 85 [2] 4f 8e [2] 54 c0 [2] 69 }

  condition:
    any of them
}