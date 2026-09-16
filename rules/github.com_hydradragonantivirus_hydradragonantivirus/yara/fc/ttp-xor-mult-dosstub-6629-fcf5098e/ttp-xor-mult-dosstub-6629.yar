rule TTP_XOR_MULT_DOSStub_6629 {
  strings:
    $key_6629 = { 32 41 [2] 46 59 [2] 01 5b [2] 46 4a [2] 08 46 [2] 04 4c [2] 13 47 [2] 08 09 [2] 35 }

  condition:
    any of them
}