rule TTP_XOR_MULT_DOSStub_6619 {
  strings:
    $key_6619 = { 32 71 [2] 46 69 [2] 01 6b [2] 46 7a [2] 08 76 [2] 04 7c [2] 13 77 [2] 08 39 [2] 35 }

  condition:
    any of them
}