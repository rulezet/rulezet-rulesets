rule TTP_XOR_MULT_DOSStub_3fe6 {
  strings:
    $key_3fe6 = { 6b 8e [2] 1f 96 [2] 58 94 [2] 1f 85 [2] 51 89 [2] 5d 83 [2] 4a 88 [2] 51 c6 [2] 6c }

  condition:
    any of them
}