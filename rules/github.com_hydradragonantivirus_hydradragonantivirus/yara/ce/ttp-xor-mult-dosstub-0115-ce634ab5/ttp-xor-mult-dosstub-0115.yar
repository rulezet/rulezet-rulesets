rule TTP_XOR_MULT_DOSStub_0115 {
  strings:
    $key_0115 = { 55 7d [2] 21 65 [2] 66 67 [2] 21 76 [2] 6f 7a [2] 63 70 [2] 74 7b [2] 6f 35 [2] 52 }

  condition:
    any of them
}