rule TTP_XOR_MULT_DOSStub_6608 {
  strings:
    $key_6608 = { 32 60 [2] 46 78 [2] 01 7a [2] 46 6b [2] 08 67 [2] 04 6d [2] 13 66 [2] 08 28 [2] 35 }

  condition:
    any of them
}