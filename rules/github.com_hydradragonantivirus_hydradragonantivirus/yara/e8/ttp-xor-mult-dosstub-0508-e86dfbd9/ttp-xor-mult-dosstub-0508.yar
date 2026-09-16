rule TTP_XOR_MULT_DOSStub_0508 {
  strings:
    $key_0508 = { 51 60 [2] 25 78 [2] 62 7a [2] 25 6b [2] 6b 67 [2] 67 6d [2] 70 66 [2] 6b 28 [2] 56 }

  condition:
    any of them
}