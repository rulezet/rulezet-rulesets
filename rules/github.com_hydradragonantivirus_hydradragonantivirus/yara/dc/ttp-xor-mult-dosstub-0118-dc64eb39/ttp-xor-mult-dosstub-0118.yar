rule TTP_XOR_MULT_DOSStub_0118 {
  strings:
    $key_0118 = { 55 70 [2] 21 68 [2] 66 6a [2] 21 7b [2] 6f 77 [2] 63 7d [2] 74 76 [2] 6f 38 [2] 52 }

  condition:
    any of them
}