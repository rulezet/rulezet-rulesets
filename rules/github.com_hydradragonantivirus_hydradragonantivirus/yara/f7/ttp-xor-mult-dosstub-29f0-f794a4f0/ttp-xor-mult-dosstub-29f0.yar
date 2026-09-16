rule TTP_XOR_MULT_DOSStub_29f0 {
  strings:
    $key_29f0 = { 7d 98 [2] 09 80 [2] 4e 82 [2] 09 93 [2] 47 9f [2] 4b 95 [2] 5c 9e [2] 47 d0 [2] 7a }

  condition:
    any of them
}