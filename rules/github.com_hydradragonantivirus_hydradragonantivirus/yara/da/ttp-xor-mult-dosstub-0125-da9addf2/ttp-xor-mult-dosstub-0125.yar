rule TTP_XOR_MULT_DOSStub_0125 {
  strings:
    $key_0125 = { 55 4d [2] 21 55 [2] 66 57 [2] 21 46 [2] 6f 4a [2] 63 40 [2] 74 4b [2] 6f 05 [2] 52 }

  condition:
    any of them
}