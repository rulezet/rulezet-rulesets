rule TTP_XOR_MULT_DOSStub_0124 {
  strings:
    $key_0124 = { 55 4c [2] 21 54 [2] 66 56 [2] 21 47 [2] 6f 4b [2] 63 41 [2] 74 4a [2] 6f 04 [2] 52 }

  condition:
    any of them
}