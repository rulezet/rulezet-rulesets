rule TTP_XOR_MULT_DOSStub_3673 {
  strings:
    $key_3673 = { 62 1b [2] 16 03 [2] 51 01 [2] 16 10 [2] 58 1c [2] 54 16 [2] 43 1d [2] 58 53 [2] 65 }

  condition:
    any of them
}