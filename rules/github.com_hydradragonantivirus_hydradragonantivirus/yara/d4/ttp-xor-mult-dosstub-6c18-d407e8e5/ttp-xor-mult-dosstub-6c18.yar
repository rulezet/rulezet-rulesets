rule TTP_XOR_MULT_DOSStub_6c18 {
  strings:
    $key_6c18 = { 38 70 [2] 4c 68 [2] 0b 6a [2] 4c 7b [2] 02 77 [2] 0e 7d [2] 19 76 [2] 02 38 [2] 3f }

  condition:
    any of them
}