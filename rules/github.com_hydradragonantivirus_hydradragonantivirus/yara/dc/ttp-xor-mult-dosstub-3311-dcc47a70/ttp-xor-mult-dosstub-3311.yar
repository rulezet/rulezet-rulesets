rule TTP_XOR_MULT_DOSStub_3311 {
  strings:
    $key_3311 = { 67 79 [2] 13 61 [2] 54 63 [2] 13 72 [2] 5d 7e [2] 51 74 [2] 46 7f [2] 5d 31 [2] 60 }

  condition:
    any of them
}