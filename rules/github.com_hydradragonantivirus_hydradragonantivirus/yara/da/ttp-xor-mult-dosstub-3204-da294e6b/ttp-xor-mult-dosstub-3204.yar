rule TTP_XOR_MULT_DOSStub_3204 {
  strings:
    $key_3204 = { 66 6c [2] 12 74 [2] 55 76 [2] 12 67 [2] 5c 6b [2] 50 61 [2] 47 6a [2] 5c 24 [2] 61 }

  condition:
    any of them
}