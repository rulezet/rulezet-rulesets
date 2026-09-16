rule TTP_XOR_MULT_DOSStub_5673 {
  strings:
    $key_5673 = { 02 1b [2] 76 03 [2] 31 01 [2] 76 10 [2] 38 1c [2] 34 16 [2] 23 1d [2] 38 53 [2] 05 }

  condition:
    any of them
}