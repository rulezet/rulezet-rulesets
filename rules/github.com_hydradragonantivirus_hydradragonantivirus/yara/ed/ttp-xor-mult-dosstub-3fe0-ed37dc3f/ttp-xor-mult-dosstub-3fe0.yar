rule TTP_XOR_MULT_DOSStub_3fe0 {
  strings:
    $key_3fe0 = { 6b 88 [2] 1f 90 [2] 58 92 [2] 1f 83 [2] 51 8f [2] 5d 85 [2] 4a 8e [2] 51 c0 [2] 6c }

  condition:
    any of them
}