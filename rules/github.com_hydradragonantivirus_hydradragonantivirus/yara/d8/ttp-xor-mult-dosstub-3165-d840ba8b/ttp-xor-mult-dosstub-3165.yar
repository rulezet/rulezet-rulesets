rule TTP_XOR_MULT_DOSStub_3165 {
  strings:
    $key_3165 = { 65 0d [2] 11 15 [2] 56 17 [2] 11 06 [2] 5f 0a [2] 53 00 [2] 44 0b [2] 5f 45 [2] 62 }

  condition:
    any of them
}