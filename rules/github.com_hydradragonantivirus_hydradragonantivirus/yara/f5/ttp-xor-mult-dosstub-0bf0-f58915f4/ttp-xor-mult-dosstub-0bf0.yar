rule TTP_XOR_MULT_DOSStub_0bf0 {
  strings:
    $key_0bf0 = { 5f 98 [2] 2b 80 [2] 6c 82 [2] 2b 93 [2] 65 9f [2] 69 95 [2] 7e 9e [2] 65 d0 [2] 58 }

  condition:
    any of them
}