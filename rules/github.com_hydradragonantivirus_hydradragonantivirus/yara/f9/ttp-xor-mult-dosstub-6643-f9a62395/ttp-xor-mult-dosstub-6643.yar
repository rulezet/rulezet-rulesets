rule TTP_XOR_MULT_DOSStub_6643 {
  strings:
    $key_6643 = { 32 2b [2] 46 33 [2] 01 31 [2] 46 20 [2] 08 2c [2] 04 26 [2] 13 2d [2] 08 63 [2] 35 }

  condition:
    any of them
}