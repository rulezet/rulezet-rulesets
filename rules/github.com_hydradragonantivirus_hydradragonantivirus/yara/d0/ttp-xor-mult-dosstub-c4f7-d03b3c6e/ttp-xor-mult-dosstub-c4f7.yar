rule TTP_XOR_MULT_DOSStub_c4f7 {
  strings:
    $key_c4f7 = { 90 9f [2] e4 87 [2] a3 85 [2] e4 94 [2] aa 98 [2] a6 92 [2] b1 99 [2] aa d7 [2] 97 }

  condition:
    any of them
}