rule TTP_XOR_MULT_DOSStub_1bf0 {
  strings:
    $key_1bf0 = { 4f 98 [2] 3b 80 [2] 7c 82 [2] 3b 93 [2] 75 9f [2] 79 95 [2] 6e 9e [2] 75 d0 [2] 48 }

  condition:
    any of them
}