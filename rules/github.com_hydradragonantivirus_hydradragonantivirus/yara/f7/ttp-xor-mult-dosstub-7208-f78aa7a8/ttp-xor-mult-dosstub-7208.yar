rule TTP_XOR_MULT_DOSStub_7208 {
  strings:
    $key_7208 = { 26 60 [2] 52 78 [2] 15 7a [2] 52 6b [2] 1c 67 [2] 10 6d [2] 07 66 [2] 1c 28 [2] 21 }

  condition:
    any of them
}