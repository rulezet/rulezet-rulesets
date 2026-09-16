rule TTP_XOR_MULT_DOSStub_0163 {
  strings:
    $key_0163 = { 55 0b [2] 21 13 [2] 66 11 [2] 21 00 [2] 6f 0c [2] 63 06 [2] 74 0d [2] 6f 43 [2] 52 }

  condition:
    any of them
}