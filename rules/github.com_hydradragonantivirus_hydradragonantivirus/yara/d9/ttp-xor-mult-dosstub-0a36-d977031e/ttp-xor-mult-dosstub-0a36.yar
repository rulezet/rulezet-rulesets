rule TTP_XOR_MULT_DOSStub_0a36 {
  strings:
    $key_0a36 = { 5e 5e [2] 2a 46 [2] 6d 44 [2] 2a 55 [2] 64 59 [2] 68 53 [2] 7f 58 [2] 64 16 [2] 59 }

  condition:
    any of them
}