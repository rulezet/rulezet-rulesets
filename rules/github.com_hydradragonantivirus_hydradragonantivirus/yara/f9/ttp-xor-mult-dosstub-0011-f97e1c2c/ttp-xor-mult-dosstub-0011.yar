rule TTP_XOR_MULT_DOSStub_0011 {
  strings:
    $key_0011 = { 54 79 [2] 20 61 [2] 67 63 [2] 20 72 [2] 6e 7e [2] 62 74 [2] 75 7f [2] 6e 31 [2] 53 }

  condition:
    any of them
}