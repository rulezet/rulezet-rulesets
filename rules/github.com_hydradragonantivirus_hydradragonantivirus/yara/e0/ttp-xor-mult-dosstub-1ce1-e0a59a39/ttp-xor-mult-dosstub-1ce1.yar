rule TTP_XOR_MULT_DOSStub_1ce1 {
  strings:
    $key_1ce1 = { 48 89 [2] 3c 91 [2] 7b 93 [2] 3c 82 [2] 72 8e [2] 7e 84 [2] 69 8f [2] 72 c1 [2] 4f }

  condition:
    any of them
}