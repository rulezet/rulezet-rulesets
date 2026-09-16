rule TTP_XOR_MULT_DOSStub_29f6 {
  strings:
    $key_29f6 = { 7d 9e [2] 09 86 [2] 4e 84 [2] 09 95 [2] 47 99 [2] 4b 93 [2] 5c 98 [2] 47 d6 [2] 7a }

  condition:
    any of them
}