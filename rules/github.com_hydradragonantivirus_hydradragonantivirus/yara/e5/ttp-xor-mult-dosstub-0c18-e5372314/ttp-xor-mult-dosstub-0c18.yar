rule TTP_XOR_MULT_DOSStub_0c18 {
  strings:
    $key_0c18 = { 58 70 [2] 2c 68 [2] 6b 6a [2] 2c 7b [2] 62 77 [2] 6e 7d [2] 79 76 [2] 62 38 [2] 5f }

  condition:
    any of them
}