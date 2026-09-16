rule TTP_XOR_MULT_DOSStub_38e6 {
  strings:
    $key_38e6 = { 6c 8e [2] 18 96 [2] 5f 94 [2] 18 85 [2] 56 89 [2] 5a 83 [2] 4d 88 [2] 56 c6 [2] 6b }

  condition:
    any of them
}