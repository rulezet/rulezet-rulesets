rule TTP_XOR_MULT_DOSStub_19f6 {
  strings:
    $key_19f6 = { 4d 9e [2] 39 86 [2] 7e 84 [2] 39 95 [2] 77 99 [2] 7b 93 [2] 6c 98 [2] 77 d6 [2] 4a }

  condition:
    any of them
}