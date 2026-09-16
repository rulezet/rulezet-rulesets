rule TTP_XOR_MULT_DOSStub_1469 {
  strings:
    $key_1469 = { 40 01 [2] 34 19 [2] 73 1b [2] 34 0a [2] 7a 06 [2] 76 0c [2] 61 07 [2] 7a 49 [2] 47 }

  condition:
    any of them
}