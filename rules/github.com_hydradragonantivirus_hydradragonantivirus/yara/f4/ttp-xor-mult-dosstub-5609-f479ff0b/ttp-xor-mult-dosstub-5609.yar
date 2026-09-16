rule TTP_XOR_MULT_DOSStub_5609 {
  strings:
    $key_5609 = { 02 61 [2] 76 79 [2] 31 7b [2] 76 6a [2] 38 66 [2] 34 6c [2] 23 67 [2] 38 29 [2] 05 }

  condition:
    any of them
}