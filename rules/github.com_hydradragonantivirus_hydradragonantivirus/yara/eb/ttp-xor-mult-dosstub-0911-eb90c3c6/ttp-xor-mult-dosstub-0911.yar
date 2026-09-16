rule TTP_XOR_MULT_DOSStub_0911 {
  strings:
    $key_0911 = { 5d 79 [2] 29 61 [2] 6e 63 [2] 29 72 [2] 67 7e [2] 6b 74 [2] 7c 7f [2] 67 31 [2] 5a }

  condition:
    any of them
}