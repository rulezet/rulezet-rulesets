rule TTP_XOR_MULT_DOSStub_6045 {
  strings:
    $key_6045 = { 34 2d [2] 40 35 [2] 07 37 [2] 40 26 [2] 0e 2a [2] 02 20 [2] 15 2b [2] 0e 65 [2] 33 }

  condition:
    any of them
}