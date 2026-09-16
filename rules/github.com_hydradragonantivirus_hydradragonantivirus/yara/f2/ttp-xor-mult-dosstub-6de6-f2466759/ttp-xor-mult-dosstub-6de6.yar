rule TTP_XOR_MULT_DOSStub_6de6 {
  strings:
    $key_6de6 = { 39 8e [2] 4d 96 [2] 0a 94 [2] 4d 85 [2] 03 89 [2] 0f 83 [2] 18 88 [2] 03 c6 [2] 3e }

  condition:
    any of them
}