rule TTP_XOR_MULT_DOSStub_0af0 {
  strings:
    $key_0af0 = { 5e 98 [2] 2a 80 [2] 6d 82 [2] 2a 93 [2] 64 9f [2] 68 95 [2] 7f 9e [2] 64 d0 [2] 59 }

  condition:
    any of them
}