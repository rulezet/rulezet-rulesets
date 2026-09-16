rule TTP_XOR_MULT_DOSStub_4c18 {
  strings:
    $key_4c18 = { 18 70 [2] 6c 68 [2] 2b 6a [2] 6c 7b [2] 22 77 [2] 2e 7d [2] 39 76 [2] 22 38 [2] 1f }

  condition:
    any of them
}