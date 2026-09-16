rule TTP_XOR_MULT_DOSStub_1c18 {
  strings:
    $key_1c18 = { 48 70 [2] 3c 68 [2] 7b 6a [2] 3c 7b [2] 72 77 [2] 7e 7d [2] 69 76 [2] 72 38 [2] 4f }

  condition:
    any of them
}