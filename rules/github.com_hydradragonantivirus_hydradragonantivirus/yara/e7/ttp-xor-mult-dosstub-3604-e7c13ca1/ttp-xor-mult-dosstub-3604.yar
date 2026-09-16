rule TTP_XOR_MULT_DOSStub_3604 {
  strings:
    $key_3604 = { 62 6c [2] 16 74 [2] 51 76 [2] 16 67 [2] 58 6b [2] 54 61 [2] 43 6a [2] 58 24 [2] 65 }

  condition:
    any of them
}