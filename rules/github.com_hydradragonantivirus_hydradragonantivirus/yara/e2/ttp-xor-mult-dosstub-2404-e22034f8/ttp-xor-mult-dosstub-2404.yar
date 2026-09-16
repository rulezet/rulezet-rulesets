rule TTP_XOR_MULT_DOSStub_2404 {
  strings:
    $key_2404 = { 70 6c [2] 04 74 [2] 43 76 [2] 04 67 [2] 4a 6b [2] 46 61 [2] 51 6a [2] 4a 24 [2] 77 }

  condition:
    any of them
}