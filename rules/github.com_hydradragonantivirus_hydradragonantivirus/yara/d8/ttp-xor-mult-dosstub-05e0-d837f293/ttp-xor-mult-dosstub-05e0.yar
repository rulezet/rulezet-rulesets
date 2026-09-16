rule TTP_XOR_MULT_DOSStub_05e0 {
  strings:
    $key_05e0 = { 51 88 [2] 25 90 [2] 62 92 [2] 25 83 [2] 6b 8f [2] 67 85 [2] 70 8e [2] 6b c0 [2] 56 }

  condition:
    any of them
}