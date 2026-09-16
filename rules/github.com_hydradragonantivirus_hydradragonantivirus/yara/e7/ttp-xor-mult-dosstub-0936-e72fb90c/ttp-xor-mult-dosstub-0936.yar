rule TTP_XOR_MULT_DOSStub_0936 {
  strings:
    $key_0936 = { 5d 5e [2] 29 46 [2] 6e 44 [2] 29 55 [2] 67 59 [2] 6b 53 [2] 7c 58 [2] 67 16 [2] 5a }

  condition:
    any of them
}