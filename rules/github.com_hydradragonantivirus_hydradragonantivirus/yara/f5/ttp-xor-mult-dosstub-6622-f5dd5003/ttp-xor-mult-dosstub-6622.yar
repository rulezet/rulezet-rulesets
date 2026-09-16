rule TTP_XOR_MULT_DOSStub_6622 {
  strings:
    $key_6622 = { 32 4a [2] 46 52 [2] 01 50 [2] 46 41 [2] 08 4d [2] 04 47 [2] 13 4c [2] 08 02 [2] 35 }

  condition:
    any of them
}