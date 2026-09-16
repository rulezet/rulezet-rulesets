rule TTP_XOR_MULT_DOSStub_24e9 {
  strings:
    $key_24e9 = { 70 81 [2] 04 99 [2] 43 9b [2] 04 8a [2] 4a 86 [2] 46 8c [2] 51 87 [2] 4a c9 [2] 77 }

  condition:
    any of them
}