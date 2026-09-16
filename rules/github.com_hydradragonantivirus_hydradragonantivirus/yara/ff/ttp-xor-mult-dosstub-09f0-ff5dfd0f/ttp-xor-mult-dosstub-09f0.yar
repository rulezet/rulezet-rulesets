rule TTP_XOR_MULT_DOSStub_09f0 {
  strings:
    $key_09f0 = { 5d 98 [2] 29 80 [2] 6e 82 [2] 29 93 [2] 67 9f [2] 6b 95 [2] 7c 9e [2] 67 d0 [2] 5a }

  condition:
    any of them
}