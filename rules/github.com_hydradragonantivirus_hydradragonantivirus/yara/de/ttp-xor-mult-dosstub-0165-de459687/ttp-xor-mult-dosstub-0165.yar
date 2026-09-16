rule TTP_XOR_MULT_DOSStub_0165 {
  strings:
    $key_0165 = { 55 0d [2] 21 15 [2] 66 17 [2] 21 06 [2] 6f 0a [2] 63 00 [2] 74 0b [2] 6f 45 [2] 52 }

  condition:
    any of them
}