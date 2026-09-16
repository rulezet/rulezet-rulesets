rule TTP_XOR_MULT_DOSStub_01f5 {
  strings:
    $key_01f5 = { 55 9d [2] 21 85 [2] 66 87 [2] 21 96 [2] 6f 9a [2] 63 90 [2] 74 9b [2] 6f d5 [2] 52 }

  condition:
    any of them
}