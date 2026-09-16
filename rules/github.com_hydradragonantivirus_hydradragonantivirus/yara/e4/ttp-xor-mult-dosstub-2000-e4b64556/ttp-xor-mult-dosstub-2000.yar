rule TTP_XOR_MULT_DOSStub_2000 {
  strings:
    $key_2000 = { 74 68 [2] 00 70 [2] 47 72 [2] 00 63 [2] 4e 6f [2] 42 65 [2] 55 6e [2] 4e 20 [2] 73 }

  condition:
    any of them
}